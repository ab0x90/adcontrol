"""
Multi-hop attack-path chaining over the control graph.

``analyze.py`` answers a one-hop question: what does a principal *directly*
control, and who *directly* controls it. This module chains those hops into a
full attack path — "how does principal A reach Domain Admin?" — by treating a
control edge as a pivot: once you control a principal you can act *as* it,
inheriting its effective SIDs, and continue from there.

The traversal reuses :attr:`analyze.Analyzer.acl_index` (``trustee_sid ->
[(target, ace)]``), which is already the edge list we need. Two modes:

  * ``"short"``  — BFS. Returns the shortest path to each reachable target,
    plus a few alternate shortest-ish paths. Fast; the default.

  * ``"full"``   — DFS enumeration of all simple (loop-free) paths up to a
    depth / count cap. Complete but noisier on dense domains.

**Pivot semantics (full pivot, BloodHound-style).** A hop expands reach only
when the right actually lets you take over the target:

  * control a **user/computer**  -> you can reset its password / act as it, so
    you inherit *its* effective SID set and keep going;
  * control a **group**          -> you can add yourself, so you gain the
    group's SID (and thus everything that SID controls);
  * reach the **domain head** holding both replication rights (DCSync), or
    reach any Tier-0 admin group -> that is a terminal win.

Rights that don't grant takeover (a scoped ReadProperty, User-Change-Password,
etc.) never create a pivot edge, so they can't inflate a path.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from adcontrol.model import ObjectStore, RawObject, Ace
from adcontrol.analyze import Analyzer
from adcontrol import rights

# Rights that let the holder fully take over / act as the target object. Only
# these create a pivot hop. Matched by prefix so scoped variants
# ("WriteProperty:msDS-KeyCredentialLink") and the synthesized DCSync edge
# ("DCSync (replicate secrets)") are covered. Kept deliberately close to the
# takeover vocabulary used by queries.py._is_takeover_right.
_PIVOT_RIGHTS = (
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "Owns",                        # "Owns (implicit WriteDacl)"
    "AllExtendedRights",
    "ForceChangePassword",
    "User-Force-Change-Password",
    "AddMember",                   # group membership write
    "Self-Membership",             # Self:Add/Remove member
    "WriteProperty:member",
    "WriteProperty:msDS-KeyCredentialLink",     # shadow credentials
    "WriteProperty:msDS-AllowedToActOnBehalfOfOtherIdentity",  # RBCD
    "WriteProperty:servicePrincipalName",       # targeted kerberoast
    "WriteProperty:Service-Principal-Name",     # SPN write (friendly-named variant)
    "WriteSPN",
    "WriteProperty:User-Account-Restrictions",  # write userAccountControl: clear
                                                # ACCOUNTDISABLE, set DONT_REQ_PREAUTH
                                                # (AS-REP roast), or TRUSTED_FOR_DELEGATION
    "WriteProperty:msDS-KeyCredentialLink",     # shadow credentials
    "msDS-KeyCredentialLink",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "WriteAllProperties",          # writes every attribute → includes the takeover ones
    "Migrate-SID-History",         # inject SID history → become any principal
    "ReadGMSAPassword",            # retrieve the gMSA managed password → auth as it
    "DCSync",                      # "DCSync (replicate secrets)"
)

# Caps for the "full" enumeration so a dense domain can't explode. The number of
# simple paths in a dense control graph can grow combinatorially, so we bound
# both how deep a chain may go and how many paths we return. find_full walks by
# increasing depth (iterative deepening) so if the cap is hit, the paths kept are
# always the *shortest* ones — a longer chain never starves out a shorter one.
_FULL_MAX_DEPTH = 6
_FULL_MAX_PATHS = 500
# "Uncapped" mode raises the path ceiling to this instead of removing it outright.
# A truly unbounded search on a dense graph produces >1e6 simple paths — which the
# time budget below survives, but the resulting JSON (tens of MB) would choke the
# browser long before the compute does. So "uncapped" means "a much larger, still
# finite ceiling": ~10k paths ≈ 12MB, the practical limit of what a page can render.
_FULL_UNCAPPED_MAX = 10000
# Wall-clock backstop (seconds). Applies to EVERY full enumeration, capped or
# uncapped — a dense control graph can hold hundreds of thousands of simple paths,
# so the ceiling alone is not enough; this guarantees the search always returns.
_FULL_TIME_BUDGET_S = 15.0
# For "short", how many alternate shortest-ish paths to keep per target.
_SHORT_ALTS = 3


def is_pivot_right(right: str) -> bool:
    """True when holding *right* over a principal lets you take it over and
    thus continue the chain from it."""
    return any(right.startswith(p) for p in _PIVOT_RIGHTS)


@dataclass
class PathHop:
    """One control hop in an attack path: the object you act as, the right you
    hold over the next object, and where you land."""
    source_sid: str
    source_label: str
    target_dn: str
    target_label: str
    target_class: str
    right: str
    severity: str
    via: str = ""          # how the right is held at this hop: "direct" / "group: X"

    def as_json(self) -> dict:
        return {
            "source_sid": self.source_sid, "source_label": self.source_label,
            "target_dn": self.target_dn, "target_label": self.target_label,
            "target_class": self.target_class, "right": self.right,
            "severity": self.severity, "via": self.via,
        }


@dataclass
class AttackPath:
    """An ordered chain of hops from the subject to a high-value target."""
    hops: list[PathHop] = field(default_factory=list)
    target_dn: str = ""
    target_label: str = ""
    win: str = ""          # short reason this target is a win, e.g. "Domain Admins"

    @property
    def length(self) -> int:
        return len(self.hops)

    def as_json(self) -> dict:
        return {
            "length": self.length,
            "target_dn": self.target_dn,
            "target_label": self.target_label,
            "win": self.win,
            "hops": [h.as_json() for h in self.hops],
        }


@dataclass
class PathResult:
    """The outcome of a path search: the paths plus whether the search was cut
    short. ``truncated`` is set when enumeration stopped early — the paths are
    still the *shortest* ones found (iterative deepening), but deeper alternates
    may be missing. ``reason`` is 'count' (hit the path cap) or 'time' (hit the
    wall-clock budget); ``limit`` is the numeric cap that fired."""
    paths: list[AttackPath] = field(default_factory=list)
    truncated: bool = False
    reason: str = ""            # "" | "count" | "time"
    limit: float = 0

    def as_json(self) -> dict:
        return {
            "count": len(self.paths),
            "truncated": self.truncated,
            "truncated_reason": self.reason,
            "truncated_limit": self.limit,
            "paths": [p.as_json() for p in self.paths],
        }


class PathFinder:
    """Chains control hops over an :class:`Analyzer`'s ACL index."""

    def __init__(self, analyzer: Analyzer):
        self.az = analyzer
        self.store: ObjectStore = analyzer.store
        self.graph = analyzer.graph

    # -- target selection -----------------------------------------------------
    # SIDs whose membership marks a computer as a Domain Controller — owning a
    # DC computer account is a domain compromise (RBCD/S4U to SYSTEM, DCSync,
    # dump the NTDS), so DCs are Tier-0 goals in their own right.
    _DC_MEMBER_SIDS = {"S-1-5-9"}          # Enterprise Domain Controllers
    _DC_MEMBER_RIDS = {"516", "521", "498"}  # Domain Controllers / RODCs / Enterprise RODCs

    def _is_domain_controller(self, obj: RawObject) -> bool:
        if obj.object_class != "computer":
            return False
        for sid in self.graph.effective_sids(obj):
            if sid in self._DC_MEMBER_SIDS:
                return True
            if sid.startswith("S-1-5-21-") and sid.rsplit("-", 1)[-1] in self._DC_MEMBER_RIDS:
                return True
        return False

    def _tier0_linked_gpos(self) -> dict[str, str]:
        """GPOs whose control is a Tier-0 win, because the GPO is linked to a
        container whose scope includes Tier-0 assets. Controlling such a GPO lets
        you push a scheduled/immediate task, script, or Restricted-Groups change
        and run code against those assets. Three cases, in order of blast radius:

          * linked to the **domain root** -> affects everything;
          * linked to the **Domain Controllers OU** -> code on the DCs;
          * linked to any **OU that contains a Tier-0 principal** (a member of a
            built-in admin group, or a DC computer) -> compromise that principal.

        "Contains" is resolved by DN nesting (the principal's DN sits under the
        OU's DN) — always available, unlike BloodHound's GPOChanges/AffectedComputers
        which are frequently empty in exports. Resolved from ``gplinks`` on the
        OU/domain, matched to GPO objects by EITHER identifier — the two
        collectors populate ``gplinks`` differently: the live collector's
        ``_parse_gplink`` (collector.py) stores the linked GPO's full **DN**
        (straight from LDAP's gPLink), while the BloodHound importer stores the
        GPO's **GUID** (``Links[].GUID``/``ObjectIdentifier``). Matching only one
        of the two silently drops every Tier-0-linked GPO on whichever source
        wasn't matched — caught when a live GOAD scan showed zero GPO targets
        despite a GPO linked straight to the domain root. Degrades to {} when
        link data is absent, so no false Tier-0 GPOs are invented."""
        gpo_by_key = {}
        for o in self.store.objects.values():
            if o.object_class in ("groupPolicyContainer", "gpo"):
                for key in (o.guid, o.sid, o.dn):
                    if key:
                        gpo_by_key[key.upper()] = o

        # Tier-0 principals whose DN we can locate under an OU.
        tier0_dns = []
        for o in self.store.objects.values():
            if o.object_class not in ("user", "computer", "group"):
                continue
            if any(rights.is_builtin_admin_trustee(s) for s in self.graph.effective_sids(o)) \
                    or self._is_domain_controller(o):
                tier0_dns.append((o.dn.upper(), o.label))

        def tier0_under(ou_dn: str):
            """Labels of Tier-0 principals whose DN is nested under *ou_dn*."""
            suffix = "," + ou_dn.upper()
            return [lbl for dn, lbl in tier0_dns if dn.endswith(suffix)]

        out: dict[str, str] = {}
        for cont in self.store.objects.values():
            if cont.object_class == "domain":
                reach = "the whole domain"
            elif cont.object_class == "organizationalUnit" \
                    and "domain controllers" in cont.label.lower():
                reach = "Domain Controllers"
            elif cont.object_class == "organizationalUnit":
                affected = tier0_under(cont.dn)
                if not affected:
                    continue   # OU has no Tier-0 principal under it — not a win
                sample = ", ".join(affected[:3]) + (f" +{len(affected)-3}" if len(affected) > 3 else "")
                reach = f"OU {cont.label} — affects Tier-0: {sample}"
            else:
                continue
            for link in cont.gplinks:
                g = gpo_by_key.get(link.upper())
                if g is not None:
                    out[g.dn] = f"{g.label} (GPO linked to {reach})"
        return out

    def tier0_targets(self) -> dict[str, str]:
        """Map of target DN -> win-reason for the default Tier-0 goal set:
        built-in admin groups, the domain head (DCSync/root), every Domain
        Controller computer account, and every GPO linked to the DC OU / domain
        root (controlling it pushes code to Tier-0 assets). Once controlled, these
        mean game over."""
        try:
            return self._tier0_cache
        except AttributeError:
            pass
        targets: dict[str, str] = {}
        for obj in self.store.objects.values():
            if obj.sid and rights.is_builtin_admin_trustee(obj.sid) \
                    and obj.object_class in ("group", "domain"):
                targets[obj.dn] = obj.label
            elif self._is_domain_controller(obj):
                targets[obj.dn] = obj.label + " (Domain Controller)"
        if self.az._domain_head:
            targets.setdefault(self.az._domain_head.dn,
                               self.az._domain_head.label + " (domain root / DCSync)")
        targets.update(self._tier0_linked_gpos())
        self._tier0_cache = targets
        return targets

    def _becomes_tier0(self, obj: RawObject) -> str:
        """If taking over *obj* makes you effectively Tier-0 in its own right —
        it is a member of a built-in admin group, or a Domain Controller — return
        a short win reason; else "". This catches wins where the chain lands on a
        *principal that already holds Tier-0* (e.g. a Domain Admin whose creds you
        steal from a session, or whose password you reset), rather than only when
        it lands on a Tier-0 object. The subject's own DN is never counted (that's
        the already_tier0 short-circuit)."""
        if obj.object_class not in ("user", "computer"):
            return ""      # groups are handled as target objects; avoid double-counting
        if self._is_domain_controller(obj):
            return obj.label + " (Domain Controller)"
        for sid in self.graph.group_sids_for(obj):
            if rights.is_builtin_admin_trustee(sid):
                return f"{obj.label} (member of {self.graph.label_for_sid(sid)})"
        return ""

    # -- one-hop expansion (the pivot step) -----------------------------------
    def _pivot_sids(self, obj: RawObject) -> set[str]:
        """The effective SID set you gain by taking over *obj*. Controlling a
        principal lets you act as it (its own SID + its groups); controlling a
        group additionally means you can join it."""
        sids = set(self.graph.effective_sids(obj))
        if obj.sid:
            sids.add(obj.sid)
        return sids

    def _outgoing(self, actor: RawObject, sids: set[str]):
        """Yield (target_obj, ace, holder_sid) for every pivot avenue out of the
        node we're currently acting as (*actor*, whose effective SID set is
        *sids*), skipping self-edges.

        Deduped by (target_dn, right): the store can carry the same right on a
        target more than once (duplicate ACEs, or the owner materialized as an
        ``Owns`` ACE alongside a real WriteDacl), and several of the actor's
        SIDs can grant the same right on the same target. We keep just one hop
        per (target, right) so a path can't be padded with redundant edges. The
        first holder SID seen wins (it drives the ``via`` explanation)."""
        exclude_dn = actor.dn
        idx = self.az.acl_index
        seen: set[tuple[str, str]] = set()
        for sid in sids:
            for target, ace in idx.get(sid, ()):
                if target.dn == exclude_dn:
                    continue
                if not is_pivot_right(ace.right):
                    continue
                k = (target.dn, ace.right)
                if k in seen:
                    continue
                seen.add(k)
                yield target, ace, sid
        # Synthesized DCSync: holding BOTH replication rights on the domain head is
        # a domain-root win, but neither raw right is a pivot on its own — so we
        # must re-run the synthesis for EVERY pivot node (analyze.py only does it
        # for the subject's own SIDs). Without this a chain like
        # alice → svc → [svc holds both repl rights] → DCSync is missed entirely.
        dcsync = self._synth_dcsync_hop(sids, exclude_dn)
        if dcsync is not None:
            yield dcsync
        # Local-admin pivot: if any SID we act as is a member of local
        # Administrators on a host, we control that host — hop INTO the computer
        # object. The next iteration treats that computer as the actor, so the
        # session pivot below fires and we can steal any reliable session on it.
        # (host-plane data comes from SharpHound LocalGroups / live SAMR.)
        hai = self.az.host_admin_index
        for sid in sids:
            for comp_dn in hai.get(sid, ()):
                if comp_dn == exclude_dn:
                    continue
                comp = self.store.by_dn(comp_dn)
                if comp is None:
                    continue
                k = (comp_dn, "LocalAdmin")
                if k in seen:
                    continue
                seen.add(k)
                ace = Ace(trustee_sid=sid,
                          right="LocalAdmin — control host",
                          severity="high")
                yield comp, ace, sid
        # Session pivot: if we control a COMPUTER, every user with a reliable
        # (privileged/registry) logon session on it is a takeover — steal the
        # token / dump creds and act as that user. Yields a synthetic HasSession
        # hop into each such user. (Plain net-sessions are excluded — too stale.)
        if actor.object_class == "computer" and actor.sid:
            for target, ace, holder in self._session_hops(actor):
                if target.dn == exclude_dn:
                    continue
                yield target, ace, holder

    def _session_hops(self, comp: RawObject):
        """(user_obj, synthetic HasSession ace, user_sid) for each reliable
        session on computer *comp*. Deduped per user."""
        seen_users: set[str] = set()
        for sess in self.store.sessions_on_host(comp.sid):
            if sess.kind not in ("privileged", "registry"):
                continue
            if sess.user_sid in seen_users:
                continue
            u = self.store.by_sid(sess.user_sid)
            if u is None or u.object_class != "user":
                continue
            seen_users.add(sess.user_sid)
            ace = Ace(trustee_sid=comp.sid,
                      right=f"HasSession ({sess.kind}) — steal creds",
                      severity="high")
            yield u, ace, comp.sid

    def _synth_dcsync_hop(self, sids: set[str], exclude_dn: str):
        """If any SID in *sids* holds both DS-Replication-Get-Changes and
        -Get-Changes-All on the domain head, return a (domain, synthetic-ace,
        holder_sid) triple representing the DCSync win; else None."""
        head = self.az._domain_head
        if head is None or head.dn == exclude_dn:
            return None
        held = {}   # right -> holder sid, restricted to our sids
        for a in head.aces:
            if a.trustee_sid in sids and not a.right.startswith("DENY:"):
                held[a.right] = a.trustee_sid
        if "DS-Replication-Get-Changes" in held and "DS-Replication-Get-Changes-All" in held:
            holder = held["DS-Replication-Get-Changes-All"]
            ace = Ace(trustee_sid=holder, right="DCSync (replicate secrets)",
                      severity="high")
            return head, ace, holder
        return None

    def _hop(self, actor: RawObject, target: RawObject, ace, holder_sid: str) -> PathHop:
        return PathHop(
            source_sid=actor.sid or holder_sid,
            source_label=actor.label,
            target_dn=target.dn,
            target_label=target.label,
            target_class=target.object_class,
            right=ace.right,
            severity=ace.severity,
            via=self.az._explain_via(actor, holder_sid),
        )

    # -- BFS: shortest paths (short mode) -------------------------------------
    def find_short(self, subject: RawObject, targets: dict[str, str]) -> list[AttackPath]:
        """Shortest path to each reachable target (BFS over pivot edges), plus a
        few alternate shortest-length paths per target."""
        if subject.dn in targets:
            return []   # already there
        results: list[AttackPath] = []
        found_len: dict[str, int] = {}   # target_dn -> shortest length found
        alt_count: dict[str, int] = {}

        # BFS frontier carries the object we're acting as and the hop list so far.
        start = deque([(subject, [])])
        visited: set[str] = {subject.dn}

        while start:
            actor, hops = start.popleft()
            if len(hops) >= _FULL_MAX_DEPTH:
                continue
            sids = self._pivot_sids(actor)
            for target, ace, holder_sid in self._outgoing(actor, sids):
                # Avoid revisiting an object already on this path (simple path).
                if any(h.target_dn == target.dn for h in hops):
                    continue
                new_hops = hops + [self._hop(actor, target, ace, holder_sid)]

                # Win if the target IS a Tier-0 goal object, or is a principal that
                # already effectively holds Tier-0 (member of an admin group / DC).
                win = targets.get(target.dn) or self._becomes_tier0(target)
                if win:
                    L = len(new_hops)
                    if target.dn not in found_len:
                        found_len[target.dn] = L
                        alt_count[target.dn] = 0
                    if L <= found_len[target.dn] and alt_count[target.dn] <= _SHORT_ALTS:
                        alt_count[target.dn] += 1
                        results.append(AttackPath(
                            hops=new_hops, target_dn=target.dn,
                            target_label=target.label, win=win))
                    continue  # a goal is terminal — don't pivot through it

                # Only pivot-worthy principals extend the frontier.
                if target.object_class in ("user", "group", "computer") \
                        and target.dn not in visited:
                    visited.add(target.dn)
                    start.append((target, new_hops))

        results = self._collapse_by_route(results)
        results.sort(key=lambda p: (p.length, p.target_label.lower()))
        return results

    _SEV_RANK = {"high": 0, "medium": 1, "low": 2}

    def _collapse_by_route(self, paths: list[AttackPath]) -> list[AttackPath]:
        """Collapse paths that traverse the *same node sequence* but differ only
        in which right was used on a hop (e.g. WriteDacl vs WriteOwner vs
        GenericAll on the same pivot). Keeps one representative per route — the
        one whose worst hop-severity is highest — so short mode stays concise.
        The kept path still shows its concrete rights per hop."""
        best: dict[tuple, AttackPath] = {}
        for p in paths:
            route = tuple([p.hops[0].source_sid] + [h.target_dn for h in p.hops]) if p.hops else ()
            worst = min((self._SEV_RANK.get(h.severity, 9) for h in p.hops), default=9)
            cur = best.get(route)
            if cur is None:
                best[route] = p
                continue
            cur_worst = min((self._SEV_RANK.get(h.severity, 9) for h in cur.hops), default=9)
            if worst < cur_worst:
                best[route] = p
        return list(best.values())

    # -- DFS: all simple paths (full mode) ------------------------------------
    def find_full(self, subject: RawObject, targets: dict[str, str],
                  path_cap: int | None = _FULL_MAX_PATHS,
                  time_budget_s: float = _FULL_TIME_BUDGET_S) -> PathResult:
        """All simple (loop-free) paths to any target, up to the depth cap.

        Walked by **iterative deepening**: we enumerate every path of length 1,
        then length 2, and so on. This guarantees that if a limit is reached, the
        paths we keep are the shortest ones — a deep chain can never crowd out a
        shorter, more actionable one (which a plain DFS would, by diving deep
        before exhausting the near edges).

        Two independent limits, either of which sets ``truncated``:
          * ``path_cap`` — max paths to collect. ``None`` means *uncapped* count
            (see the wall-clock backstop below — uncapped never means unbounded).
          * ``time_budget_s`` — wall-clock backstop that ALWAYS applies, even
            when ``path_cap`` is None. On a dense graph the simple-path count is
            combinatorial, so this is what actually prevents a hang.
        """
        res = PathResult()
        if subject.dn in targets:
            return res
        results = res.paths
        deadline = time.monotonic() + time_budget_s

        def hit_cap() -> bool:
            if path_cap is not None and len(results) >= path_cap:
                res.truncated = True
                if not res.reason:
                    res.reason, res.limit = "count", path_cap
                return True
            if time.monotonic() >= deadline:
                res.truncated = True
                if not res.reason:
                    res.reason, res.limit = "time", time_budget_s
                return True
            return False

        def dfs(actor, hops, on_path, limit):
            # Depth-bounded DFS that only *records* target hits at exactly `limit`
            # hops, so each deepening pass adds only paths of that new length.
            depth = len(hops)
            sids = self._pivot_sids(actor)
            for target, ace, holder_sid in self._outgoing(actor, sids):
                if hit_cap():
                    return
                if target.dn in on_path:
                    continue
                new_hops = hops + [self._hop(actor, target, ace, holder_sid)]
                win = targets.get(target.dn) or self._becomes_tier0(target)
                if win:
                    if depth + 1 == limit:
                        results.append(AttackPath(
                            hops=new_hops, target_dn=target.dn,
                            target_label=target.label, win=win))
                    continue        # a goal is terminal — never pivot through it
                if depth + 1 < limit and target.object_class in ("user", "group", "computer"):
                    dfs(target, new_hops, on_path | {target.dn}, limit)

        for limit in range(1, _FULL_MAX_DEPTH + 1):
            if hit_cap():
                break
            dfs(subject, [], {subject.dn}, limit)
        results.sort(key=lambda p: (p.length, p.target_label.lower()))
        return res

    def already_tier0(self, subject: RawObject) -> bool:
        """True when the subject is already Tier-0 — its effective SIDs include a
        built-in admin SID, or it is a Domain Controller. Game-over already, so a
        "path to Tier-0" would be noise."""
        if any(rights.is_builtin_admin_trustee(s)
               for s in self.graph.effective_sids(subject)):
            return True
        return self._is_domain_controller(subject)

    # -- public entry ---------------------------------------------------------
    # Recognized modes:
    #   "short"         BFS shortest path per target (uncapped, fast, authoritative
    #                   for reachability — never truncated).
    #   "full"          all simple paths, iterative-deepening, count-capped at
    #                   _FULL_MAX_PATHS (+ time backstop).
    #   "full-uncapped" all simple paths up to a much larger ceiling
    #                   (_FULL_UNCAPPED_MAX) plus the wall-clock backstop — "give
    #                   me everything reasonable", not literally unbounded (a true
    #                   unbounded search yields >1e6 paths / tens of MB of JSON).
    def _targets_for(self, subject, target_dn):
        if target_dn:
            tobj = self.store.by_dn(target_dn)
            return {tobj.dn: tobj.label} if tobj else {}
        if self.already_tier0(subject):
            return {}
        return self.tier0_targets()

    def find_result(self, subject: RawObject, mode: str = "short",
                    target_dn: str | None = None) -> PathResult:
        """Find attack paths from *subject*, returning a :class:`PathResult` that
        also reports whether enumeration was truncated. *target_dn* picks a single
        explicit goal; otherwise the Tier-0 goal set is used (and an already-Tier-0
        subject yields nothing)."""
        # An explicit already-Tier-0 subject with no explicit target has no
        # targets — but _targets_for returns {} for that AND for a bad target_dn,
        # so distinguish: only the tier0-goal path should short-circuit here.
        targets = self._targets_for(subject, target_dn)
        if not targets:
            return PathResult()
        if mode == "full":
            return self.find_full(subject, targets)
        if mode == "full-uncapped":
            return self.find_full(subject, targets, path_cap=_FULL_UNCAPPED_MAX)
        return PathResult(paths=self.find_short(subject, targets))

    def find(self, subject: RawObject, mode: str = "short",
             target_dn: str | None = None) -> list[AttackPath]:
        """Backward-compatible list-returning wrapper over :meth:`find_result`.
        Callers that need the truncation flag should use ``find_result``."""
        return self.find_result(subject, mode=mode, target_dn=target_dn).paths
