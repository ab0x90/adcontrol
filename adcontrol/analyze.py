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
        """Objects the subject can control."""
        eff = self.graph.effective_sids(subject)
        # For explaining "via", know which SID maps to which label.
        edges: list[ControlEdge] = []
        for target in self.store.objects.values():
            if target.dn == subject.dn:
                continue
            for ace in target.aces:
                if ace.right.startswith("DENY:"):
                    continue
                if ace.trustee_sid not in eff:
                    continue
                if ace.right in _NOISE_RIGHTS:
                    continue
                via = self._explain_via(subject, ace.trustee_sid)
                edges.append(ControlEdge(
                    source_sid=ace.trustee_sid,
                    source_label=subject.label,
                    target_dn=target.dn,
                    target_label=target.label,
                    target_class=target.object_class,
                    right=ace.right,
                    severity=ace.severity,
                    applies_to=ace.applies_to,
                    via=via,
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
            },
            "outbound": out,
            "inbound": inb,
            "policy_rights": self.policy_rights_for(subject),
            "outbound_high": sum(1 for e in out if e.severity == "high"),
            "inbound_high": sum(1 for e in inb if e.severity == "high"),
            "effective_group_count": len(self.graph.group_sids_for(subject)),
        }
