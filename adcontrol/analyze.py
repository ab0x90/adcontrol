"""
Control analysis over a collected :class:`~adcontrol.model.ObjectStore`.

For a chosen subject principal we compute two *separate* result sets — never
merged, so the report/GUI can present them as distinct panels:

  * **OUTBOUND** — every object the subject can control. An edge exists when any
    SID in the subject's effective SID set (self + transitive groups + implicit
    well-known groups) holds a granting (non-DENY) control ACE on the object.
    ``via`` records whether the right is held directly or through a named group.

  * **INBOUND** — every principal that can control the subject's own object,
    derived from the ACEs on the subject object itself. ``source`` is the ACE
    trustee (expanded with a note when it is a broad/everyone-ish trustee).

DCSync is synthesized as a first-class right: a trustee holding *both*
DS-Replication-Get-Changes and DS-Replication-Get-Changes-All over the domain
head is reported as a single ``DCSync`` edge (in addition to the raw replication
rights).
"""

from __future__ import annotations

from adcontrol.model import ObjectStore, RawObject, ControlEdge
from adcontrol.graph import MembershipGraph
from adcontrol import rights

# Rights that do not represent meaningful attacker control on their own — we keep
# them out of the headline edge lists (still visible in raw ACE detail).
_NOISE_RIGHTS = {
    "User-Change-Password",              # anyone can change their own pw with old pw
    "AllValidatedWrites",
}

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


class Analyzer:
    def __init__(self, store: ObjectStore):
        self.store = store
        self.graph = MembershipGraph(store)
        self._domain_head = self._find_domain_head()
        # Lazily-built reverse ACE index: trustee_sid -> list of (target, ace)
        # for every non-DENY control ACE they hold. Built once, then outbound()
        # is O(edges the subject actually holds) instead of a full-store scan —
        # collapsing the domain-wide queries from O(N^2) to O(N).
        self._acl_index: dict[str, list[tuple[RawObject, object]]] | None = None
        # Lazily-built host-plane index: trustee_sid -> set of computer-object DNs
        # that SID is a LOCAL ADMINISTRATOR on (from host-plane PolicyRight data).
        # Only local-admin is indexed (RDP alone is not a takeover pivot). Used by
        # pathfinding to chain "local admin on H → steal a session on H".
        self._host_admin_index: dict[str, set[str]] | None = None

    def _resolve_host_object(self, pr) -> "RawObject | None":
        """The computer object a host-plane PolicyRight applies to, resolved by
        SID first (reliable) then by dns/sam name against the host string."""
        if getattr(pr, "applies_to_sid", ""):
            o = self.store.by_sid(pr.applies_to_sid)
            if o is not None:
                return o
        host = (pr.applies_to or pr.source or "").lower()
        if not host:
            return None
        short = host.split(".", 1)[0]
        for obj in self.store.objects.values():
            if obj.object_class != "computer":
                continue
            dns = (obj.extra.get("dns") or "").lower()
            sam = (obj.sam.rstrip("$").lower() if obj.sam else "")
            if dns == host or (sam and sam == short):
                return obj
        return None

    def _build_host_admin_index(self) -> dict[str, set[str]]:
        idx: dict[str, set[str]] = {}
        for pr in getattr(self.store, "policy_rights", None) or []:
            if pr.plane != "host":
                continue
            r = pr.right.lower()
            if not ("local admin" in r or "administrators (local" in r):
                continue   # RDP / logon rights are not takeover pivots
            comp = self._resolve_host_object(pr)
            if comp is None or not comp.dn:
                continue
            for sid in (getattr(pr, "trustee_sids", None) or []):
                if sid:
                    idx.setdefault(sid, set()).add(comp.dn)
        return idx

    @property
    def host_admin_index(self) -> dict[str, set[str]]:
        if self._host_admin_index is None:
            self._host_admin_index = self._build_host_admin_index()
        return self._host_admin_index

    def _build_acl_index(self) -> dict[str, list[tuple]]:
        idx: dict[str, list[tuple]] = {}
        for target in self.store.objects.values():
            for ace in target.aces:
                if ace.right.startswith("DENY:") or ace.right in _NOISE_RIGHTS:
                    continue
                idx.setdefault(ace.trustee_sid, []).append((target, ace))
        return idx

    @property
    def acl_index(self) -> dict[str, list[tuple]]:
        if self._acl_index is None:
            self._acl_index = self._build_acl_index()
        return self._acl_index

    def _find_domain_head(self) -> RawObject | None:
        for obj in self.store.objects.values():
            if obj.object_class == "domain":
                return obj
        return None

    # -- built-in noise classification ----------------------------------------
    # An edge is "built-in noise" when a highly-privileged built-in trustee
    # (Administrators, Domain/Enterprise/Schema Admins, SYSTEM, …) controls an
    # infrastructure object — a container, or anything living in the
    # Configuration / Schema / System partitions. Such ACLs ship with AD and are
    # not attack paths, so the GUI can hide them. The data is still kept.
    _INFRA_CLASSES = {"container", "configuration", "rIDManager", "dnsZone"}
    _INFRA_DN_MARKERS = (
        "cn=configuration,", "cn=schema,", "cn=system,",
        "cn=domainupdates,", "cn=ntds quotas,", "cn=extended-rights,",
    )

    def _is_infra_target(self, target_class: str, target_dn: str) -> bool:
        if target_class in self._INFRA_CLASSES:
            return True
        low = target_dn.lower()
        return any(m in low for m in self._INFRA_DN_MARKERS)

    def _is_builtin_noise(self, trustee_sid: str, target_class: str, target_dn: str) -> bool:
        return (rights.is_builtin_admin_trustee(trustee_sid)
                and self._is_infra_target(target_class, target_dn))

    # -- OUTBOUND -------------------------------------------------------------
    def outbound(self, subject: RawObject) -> list[ControlEdge]:
        """Objects the subject can control.

        Uses the reverse ACL index: only the ACEs actually held by one of the
        subject's effective SIDs are visited, rather than scanning every object
        in the store. Output is identical to the naive scan.
        """
        eff = self.graph.effective_sids(subject)
        idx = self.acl_index
        edges: list[ControlEdge] = []
        for sid in eff:
            for target, ace in idx.get(sid, ()):  # DENY/noise already excluded
                if target.dn == subject.dn:
                    continue
                edges.append(ControlEdge(
                    source_sid=ace.trustee_sid,
                    source_label=subject.label,
                    target_dn=target.dn,
                    target_label=target.label,
                    target_class=target.object_class,
                    right=ace.right,
                    severity=ace.severity,
                    applies_to=ace.applies_to,
                    via=self._explain_via(subject, ace.trustee_sid),
                    inherited=ace.inherited,
                    broad=rights.is_broad_trustee(ace.trustee_sid),
                    builtin_noise=self._is_builtin_noise(
                        ace.trustee_sid, target.object_class, target.dn),
                ))
        edges += self._synthesize_dcsync_outbound(subject, eff)
        return self._dedup_sort(edges, key_target=True)

    def _explain_via(self, subject: RawObject, trustee_sid: str) -> str:
        if trustee_sid == subject.sid:
            return "direct"
        label = self.graph.label_for_sid(trustee_sid)
        if rights.is_broad_trustee(trustee_sid):
            return f"broad group: {label}"
        return f"group: {label}"

    def _synthesize_dcsync_outbound(self, subject, eff) -> list[ControlEdge]:
        if not self._domain_head:
            return []
        held = {a.right for a in self._domain_head.aces
                if a.trustee_sid in eff and not a.right.startswith("DENY:")}
        if {"DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"} <= held:
            trustee = next((a.trustee_sid for a in self._domain_head.aces
                            if a.right == "DS-Replication-Get-Changes-All"
                            and a.trustee_sid in eff), subject.sid)
            return [ControlEdge(
                source_sid=trustee, source_label=subject.label,
                target_dn=self._domain_head.dn, target_label=self._domain_head.label,
                target_class="domain", right="DCSync (replicate secrets)",
                severity="high", via=self._explain_via(subject, trustee),
                broad=rights.is_broad_trustee(trustee),
            )]
        return []

    # -- INBOUND --------------------------------------------------------------
    def inbound(self, subject: RawObject) -> list[ControlEdge]:
        """Principals that can control the subject object."""
        edges: list[ControlEdge] = []
        for ace in subject.aces:
            if ace.right.startswith("DENY:"):
                continue
            if ace.right in _NOISE_RIGHTS:
                continue
            src_label = self.graph.label_for_sid(ace.trustee_sid)
            broad = rights.is_broad_trustee(ace.trustee_sid)
            if broad:
                src_label = f"{src_label} (every domain user)"
            edges.append(ControlEdge(
                source_sid=ace.trustee_sid,
                source_label=src_label,
                target_dn=subject.dn,
                target_label=subject.label,
                target_class=subject.object_class,
                right=ace.right,
                severity=ace.severity,
                applies_to=ace.applies_to,
                via="direct" if not ace.inherited else "inherited",
                inherited=ace.inherited,
                broad=broad,
                builtin_noise=self._is_builtin_noise(
                    ace.trustee_sid, subject.object_class, subject.dn),
            ))
        # Owner of the object implicitly can rewrite its DACL.
        if subject.owner_sid and not rights.is_broad_trustee(subject.owner_sid):
            edges.append(ControlEdge(
                source_sid=subject.owner_sid,
                source_label=f"{self.graph.label_for_sid(subject.owner_sid)} (owner)",
                target_dn=subject.dn, target_label=subject.label,
                target_class=subject.object_class,
                right="Owns (implicit WriteDacl)", severity="high", via="owner",
                builtin_noise=self._is_builtin_noise(
                    subject.owner_sid, subject.object_class, subject.dn),
            ))
        return self._dedup_sort(edges, key_target=False)

    # -- helpers --------------------------------------------------------------
    @staticmethod
    def _dedup_sort(edges, key_target):
        seen = set()
        uniq = []
        for e in edges:
            key = (e.source_sid, e.target_dn, e.right, e.applies_to)
            if key in seen:
                continue
            seen.add(key)
            uniq.append(e)
        uniq.sort(key=lambda e: (
            _SEVERITY_ORDER.get(e.severity, 9),
            (e.target_label if key_target else e.source_label).lower(),
            e.right,
        ))
        return uniq

    # -- policy rights (GPO / host planes) relevant to the subject ------------
    def policy_rights_for(self, subject: RawObject) -> list:
        """PolicyRight entries (GPO-delivered / per-host) that grant this subject
        — directly or via a group it belongs to — a logon/admin right.

        Matched by label: the subject's own label plus the labels of every group
        in its effective SID set, compared case-insensitively against each
        finding's resolved trustee names (which the collectors resolved to
        labels). Well-known broad trustees (Everyone / Authenticated Users /
        Domain Users) always match a user/computer subject."""
        if not getattr(self.store, "policy_rights", None):
            return []
        want = {subject.label.lower()}
        for sid in self.graph.effective_sids(subject):
            want.add(self.graph.label_for_sid(sid).lower())
            want.add(sid.lower())
        broad_labels = {"everyone", "authenticated users", "domain users",
                        "builtin\\users", "users"}
        subject_is_principal = subject.object_class in ("user", "computer", "group")
        out = []
        for pr in self.store.policy_rights:
            trustees_low = {str(t).lower() for t in pr.trustees}
            if want & trustees_low:
                out.append(pr)
            elif subject_is_principal and (trustees_low & broad_labels):
                out.append(pr)
        return out

    # -- local admin / RDP reach (principal-anchored) -------------------------
    def local_admin_rdp_for(self, subject: RawObject) -> dict:
        """Which *systems* this subject can locally administer or RDP into.

        The host-plane PolicyRight findings are host-anchored ("who is admin on
        HOST01"). This inverts them to a principal-anchored view: given the
        subject, list every host where the subject — directly or through a group
        it belongs to — is a member of local Administrators (local admin) or can
        log on via RDP (Remote Desktop Users OR SeRemoteInteractiveLogonRight).

        Returns ``{"local_admin": [row, ...], "rdp": [row, ...]}`` where each row
        is ``{"host", "via", "severity", "right"}``. ``via`` is ``"direct"`` when
        the subject's own label matched, else ``"group: <label>"`` naming the
        group that granted it (the most specific matching trustee). Only
        meaningful for user/computer subjects; groups/others get empty lists."""
        empty = {"local_admin": [], "rdp": []}
        if subject.object_class not in ("user", "computer"):
            return empty
        if not getattr(self.store, "policy_rights", None):
            return empty

        # Map each matchable trustee label to how the subject holds it. The
        # subject's own label is "direct"; every effective-group label is that
        # group. Broad well-known trustees are treated as a group-style grant.
        own = subject.label.lower()
        via_of: dict[str, str] = {own: "direct"}
        for sid in self.graph.effective_sids(subject):
            if sid == subject.sid:
                continue
            lbl = self.graph.label_for_sid(sid)
            via_of.setdefault(lbl.lower(), f"group: {lbl}")
            via_of.setdefault(sid.lower(), f"group: {lbl}")
        broad = {"everyone": "Everyone", "authenticated users": "Authenticated Users",
                 "domain users": "Domain Users", "builtin\\users": "Users", "users": "Users"}
        for k, lbl in broad.items():
            via_of.setdefault(k, f"group: {lbl}")

        def _match_via(pr) -> str | None:
            """The best 'via' for this finding, or None if the subject isn't in
            its trustees. Prefer 'direct' over a group attribution."""
            best = None
            for t in pr.trustees:
                v = via_of.get(str(t).lower())
                if v == "direct":
                    return "direct"
                if v and best is None:
                    best = v
            return best

        local_admin, rdp = [], []
        for pr in self.store.policy_rights:
            if pr.plane != "host":
                continue
            r = pr.right.lower()
            is_admin = "local admin" in r or "administrators (local" in r
            is_rdp = "can rdp" in r or "remote desktop users" in r \
                or "seremoteinteractivelogonright" in r
            if not (is_admin or is_rdp):
                continue
            via = _match_via(pr)
            if via is None:
                continue
            row = {"host": pr.applies_to or pr.source, "via": via,
                   "severity": pr.severity, "right": pr.right}
            (local_admin if is_admin else rdp).append(row)

        def _dedup_sort(rows):
            # One row per (host, via); prefer 'direct' if a host appears both
            # ways. Sort direct-first, then by host name.
            best: dict[str, dict] = {}
            for row in rows:
                key = row["host"].lower()
                cur = best.get(key)
                if cur is None or (row["via"] == "direct" and cur["via"] != "direct"):
                    best[key] = row
            return sorted(best.values(),
                          key=lambda x: (x["via"] != "direct", x["host"].lower()))

        return {"local_admin": _dedup_sort(local_admin), "rdp": _dedup_sort(rdp)}

    @staticmethod
    def _account_flags(subject: RawObject) -> list[str]:
        """Short human labels for analysis-relevant account attributes collected
        into ``extra`` (delegation, AS-REP roast, SID history, creds-in-desc).
        Empty for objects without any."""
        e = subject.extra
        out = []
        if e.get("unconstrained_delegation"):
            out.append("Unconstrained delegation")
        if e.get("constrained_delegation_protocol_transition"):
            out.append("Constrained delegation (protocol transition)")
        if e.get("allowed_to_delegate_to"):
            out.append(f"Constrained delegation → {len(e['allowed_to_delegate_to'])} SPN(s)")
        if e.get("asrep_roastable"):
            out.append("AS-REP roastable (no pre-auth)")
        if e.get("sid_history"):
            out.append(f"SID history ({len(e['sid_history'])})")
        if e.get("description"):
            out.append("Has description (check for creds)")
        return out

    def adcs_for(self, subject: RawObject) -> list:
        """ADCS ESC findings this subject (directly or via a group) can abuse —
        as a list of plain dicts for the report/GUI. Empty when ADCS wasn't
        collected or the subject isn't an enroller/controller of any vuln
        template."""
        try:
            from adcontrol import adcs as adcs_mod
        except Exception:
            return []
        out = []
        for f in adcs_mod.findings_for_subject(self.store, subject):
            out.append({"esc": f.esc, "template": f.template, "severity": f.severity,
                        "detail": f.detail, "reasons": f.reasons})
        return out

    # -- summary --------------------------------------------------------------
    def summarize(self, subject: RawObject) -> dict:
        out = self.outbound(subject)
        inb = self.inbound(subject)
        return {
            "subject": {
                "label": subject.label, "dn": subject.dn, "sid": subject.sid,
                "class": subject.object_class, "enabled": subject.enabled,
                "admin_count": subject.admin_count,
                "spn": subject.extra.get("spn", []),
                "gmsa": bool(subject.extra.get("gmsa")),
                "materialized": bool(subject.extra.get("materialized_host_trustee")),
                "flags": self._account_flags(subject),
            },
            "outbound": out,
            "inbound": inb,
            "policy_rights": self.policy_rights_for(subject),
            "local_admin_rdp": self.local_admin_rdp_for(subject),
            "adcs": self.adcs_for(subject),
            "outbound_high": sum(1 for e in out if e.severity == "high"),
            "inbound_high": sum(1 for e in inb if e.severity == "high"),
            "effective_group_count": len(self.graph.group_sids_for(subject)),
        }
