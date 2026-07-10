"""
Transitive group-membership resolution over an :class:`~adcontrol.model.ObjectStore`.

Two things matter for control analysis:

  * **Effective SID set of a principal** — the principal's own SID plus the SIDs
    of every group it belongs to (nested, transitively), plus the implicit
    well-known groups every authenticated principal is a member of
    (Authenticated Users, Everyone, and — for users/computers — Domain Users /
    Domain Computers). An outbound control edge exists if *any* SID in this set
    holds a control right over an object.

  * **Members of a group (transitive)** — used when the chosen subject is a group
    and we want to attribute inbound control correctly, and to explain a broad
    trustee.

Cycles in AD group membership are possible; both walks are cycle-safe.
"""

from __future__ import annotations

from adcontrol.model import ObjectStore, RawObject
from adcontrol import rights

# Well-known SIDs every authenticated principal implicitly carries.
_IMPLICIT_AUTHED = {"S-1-5-11", "S-1-1-0"}  # Authenticated Users, Everyone


class MembershipGraph:
    def __init__(self, store: ObjectStore):
        self.store = store
        self._parents_cache: dict[str, set[str]] = {}   # dn -> set of group SIDs (transitive)
        self._members_cache: dict[str, set[str]] = {}   # group dn -> set of member SIDs (transitive)

    # -- upward: which groups is this principal in (transitively) --------------
    def group_sids_for(self, obj: RawObject) -> set[str]:
        """All group SIDs the object belongs to, transitively (memberOf walk)."""
        if obj.dn in self._parents_cache:
            return self._parents_cache[obj.dn]
        seen_dn: set[str] = set()
        sids: set[str] = set()
        stack = list(obj.member_of)
        while stack:
            gdn = stack.pop()
            if gdn in seen_dn:
                continue
            seen_dn.add(gdn)
            g = self.store.by_dn(gdn)
            if not g:
                continue
            if g.sid:
                sids.add(g.sid)
            stack.extend(g.member_of)
        self._parents_cache[obj.dn] = sids
        return sids

    def membership_path(self, obj: RawObject, target_sid: str) -> list[RawObject]:
        """Shortest membership chain from *obj* up to the group whose SID is
        *target_sid* (the trustee that holds a right). Returns a list of objects
        [obj, group1, group2, ..., holder]; empty if obj itself is the holder or
        no path exists. Used to draw the 'held via' chain in the modal."""
        if obj.sid == target_sid:
            return [obj]
        # BFS over memberOf edges.
        from collections import deque
        prev: dict[str, str | None] = {obj.dn: None}
        q = deque([obj.dn])
        found = None
        while q:
            dn = q.popleft()
            cur = self.store.by_dn(dn)
            if cur is None:
                continue
            for gdn in cur.member_of:
                if gdn in prev:
                    continue
                prev[gdn] = dn
                g = self.store.by_dn(gdn)
                if g is not None and g.sid == target_sid:
                    found = gdn
                    q.clear()
                    break
                q.append(gdn)
        if found is None:
            return []
        # Reconstruct path.
        chain_dns = []
        step = found
        while step is not None:
            chain_dns.append(step)
            step = prev.get(step)
        chain_dns.reverse()
        return [self.store.by_dn(d) for d in chain_dns if self.store.by_dn(d)]

    def effective_sids(self, obj: RawObject) -> set[str]:
        """The principal's own SID + all transitive group SIDs + implicit
        well-known groups. This is the set to test control rights against."""
        sids: set[str] = set()
        if obj.sid:
            sids.add(obj.sid)
        sids |= self.group_sids_for(obj)
        # Implicit memberships for any real security principal.
        if obj.object_class in ("user", "group", "computer"):
            sids |= _IMPLICIT_AUTHED
        # Domain Users / Domain Computers (RID 513 / 515) by convention.
        if self.store.domain_sid:
            if obj.object_class in ("user",):
                sids.add(f"{self.store.domain_sid}-513")
            elif obj.object_class == "computer":
                sids.add(f"{self.store.domain_sid}-515")
        return sids

    # -- downward: who is in this group (transitively) ------------------------
    def member_sids_of(self, group: RawObject) -> set[str]:
        """All principal SIDs that are members of *group*, transitively."""
        if group.dn in self._members_cache:
            return self._members_cache[group.dn]
        seen_dn: set[str] = set()
        sids: set[str] = set()
        stack = list(group.members)
        while stack:
            mdn = stack.pop()
            if mdn in seen_dn:
                continue
            seen_dn.add(mdn)
            m = self.store.by_dn(mdn)
            if not m:
                continue
            if m.sid:
                sids.add(m.sid)
            if m.object_class == "group":
                stack.extend(m.members)
        self._members_cache[group.dn] = sids
        return sids

    # -- resolve a SID to a friendly label ------------------------------------
    def label_for_sid(self, sid: str) -> str:
        obj = self.store.by_sid(sid)
        if obj:
            return obj.label
        wk = rights.wellknown_name(sid)
        if wk:
            return wk
        # Domain-relative RID against the collected domain SID.
        if self.store.domain_sid and sid.startswith(self.store.domain_sid + "-"):
            rid = sid.rsplit("-", 1)[-1]
            rn = rights.WELLKNOWN_RELATIVE.get(rid)
            if rn:
                return rn
        return sid
