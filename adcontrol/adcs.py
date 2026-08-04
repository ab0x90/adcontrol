"""
AD Certificate Services (ADCS) analysis — ESC misconfiguration detection.

Certificate templates and enrollment services live under the Configuration
naming context. A template is an AD object with a DACL (enrollment rights are
ACEs), so it flows through the same ObjectStore/ACE pipeline as everything else;
this module adds the ADCS-specific *interpretation* on top:

  * ``normalize_template`` reads the ESC-relevant template attributes into a
    common shape from either a live LDAP record or a BloodHound Properties dict.
  * ``analyze_adcs`` walks every collected template, works out who can enroll
    (or, for ESC4, who can reconfigure it), and emits :class:`AdcsFinding`
    records for the classic ESC conditions:

      - **ESC1** — low-priv can enroll, template lets the enrollee supply the
        subject (SAN), issues a client-auth cert, no manager approval / RA sig.
      - **ESC2** — low-priv can enroll a template with the Any-Purpose EKU (or no
        EKU), no approval — a cert usable for anything incl. client auth.
      - **ESC3** — low-priv can enroll a Certificate-Request-Agent (enrollment
        agent) template — mint on-behalf-of certs for other principals.
      - **ESC4** — the template OBJECT is writable by a low-priv principal
        (GenericAll/Write/WriteDacl/WriteOwner/Owns) — they can flip it into
        ESC1 and enroll.

The "low-priv can enroll/control" test reuses the store's ACEs and the same
well-known-broad-trustee logic as the rest of the tool: an enrollment right
held by Authenticated Users / Domain Users / Everyone (or by any non-Tier-0
principal) is what makes a template abusable.
"""

from __future__ import annotations

from adcontrol.model import AdcsFinding
from adcontrol import rights as R

# --- template flag bit values (MS-CRTD) ------------------------------------
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001   # msPKI-Certificate-Name-Flag
EF_PEND_ALL_REQUESTS = 0x00000002                # msPKI-Enrollment-Flag: manager approval
# NB: manager-approval bit is 0x2 in msPKI-Enrollment-Flag (CT_FLAG_PEND_ALL_REQUESTS).

# EKUs (OIDs) that make an issued cert usable for domain authentication.
_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",        # Client Authentication
    "1.3.6.1.5.2.3.4",          # PKINIT Client Authentication
    "1.3.6.1.4.1.311.20.2.2",   # Smart Card Logon
    "2.5.29.37.0",              # Any Purpose
}
_ANY_PURPOSE_EKU = "2.5.29.37.0"
_ENROLLMENT_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"   # Certificate Request Agent

# Enrollment right names our SD parser / BH importer produce.
_ENROLL_RIGHTS = ("Certificate-Enrollment", "Certificate-AutoEnrollment",
                  "Enroll", "AutoEnroll")
# Rights that mean "can reconfigure the template object" (ESC4).
_TEMPLATE_WRITE_RIGHTS = ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
                          "Owns", "WriteAllProperties", "WriteProperty")


class Template:
    """Normalized certificate-template view used for ESC analysis."""

    __slots__ = ("dn", "name", "enrollee_supplies_subject", "manager_approval",
                 "ra_signatures", "ekus", "authentication", "schema_version",
                 "no_security_extension", "cas")

    def __init__(self):
        self.dn = ""
        self.name = ""
        self.enrollee_supplies_subject = False
        self.manager_approval = False
        self.ra_signatures = 0
        self.ekus: set[str] = set()
        self.authentication = False   # issues a cert usable for auth
        self.schema_version = 1
        self.no_security_extension = False
        self.cas: list[str] = []

    @property
    def any_purpose(self) -> bool:
        return _ANY_PURPOSE_EKU in self.ekus or not self.ekus

    @property
    def enrollment_agent(self) -> bool:
        return _ENROLLMENT_AGENT_EKU in self.ekus


def _as_int(v, default=0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _eku_set(*vals) -> set[str]:
    out: set[str] = set()
    for v in vals:
        if not v:
            continue
        items = v if isinstance(v, (list, tuple, set)) else [v]
        for it in items:
            s = str(it).strip()
            if s:
                out.add(s)
    return out


def normalize_from_ldap(rec, first) -> Template:
    """Build a Template from a live LDAP record. *first* is collector._first."""
    t = Template()
    t.dn = rec.get("dn") or first(rec, "distinguishedName")
    t.name = first(rec, "displayName", "cn", "name")
    name_flag = _as_int(first(rec, "msPKI-Certificate-Name-Flag"))
    t.enrollee_supplies_subject = bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    enroll_flag = _as_int(first(rec, "msPKI-Enrollment-Flag"))
    t.manager_approval = bool(enroll_flag & EF_PEND_ALL_REQUESTS)
    t.ra_signatures = _as_int(first(rec, "msPKI-RA-Signature"))
    t.schema_version = _as_int(first(rec, "msPKI-Template-Schema-Version"), 1)
    ekus = rec.get("pKIExtendedKeyUsage") or []
    app_pol = rec.get("msPKI-Certificate-Application-Policy") or []
    t.ekus = _eku_set(ekus, app_pol)
    t.authentication = bool(t.ekus & _AUTH_EKUS) or not t.ekus
    return t


def normalize_from_bh(props) -> Template:
    """Build a Template from a BloodHound CertTemplate Properties dict."""
    t = Template()
    t.dn = props.get("distinguishedname", "") or ""
    t.name = props.get("displayname") or props.get("name") or ""
    t.enrollee_supplies_subject = bool(props.get("enrolleesuppliessubject"))
    t.manager_approval = bool(props.get("requiresmanagerapproval"))
    t.ra_signatures = _as_int(props.get("authorizedsignatures"))
    t.schema_version = _as_int(props.get("schemaversion"), 1)
    t.no_security_extension = bool(props.get("nosecurityextension"))
    t.ekus = _eku_set(props.get("effectiveekus"), props.get("ekus"))
    # BloodHound precomputes authentication-enabled; trust it, else infer.
    if "authenticationenabled" in props:
        t.authentication = bool(props.get("authenticationenabled"))
    else:
        t.authentication = bool(t.ekus & _AUTH_EKUS) or not t.ekus
    return t


def _low_priv_enrollers(store, analyzer, template_obj):
    """(labels, sids, is_broad) for principals that can ENROLL the template and
    are not themselves Tier-0. Returns the enrollers that make it abusable, or
    ([],[],False) if only privileged principals can enroll."""
    return _actors_with(store, analyzer, template_obj, _ENROLL_RIGHTS)


def _low_priv_writers(store, analyzer, template_obj):
    """Same as _low_priv_enrollers but for template-object write control (ESC4)."""
    return _actors_with(store, analyzer, template_obj, _TEMPLATE_WRITE_RIGHTS)


def _actors_with(store, analyzer, template_obj, right_prefixes):
    """Resolve the non-Tier-0 principals whose effective SIDs hold any right in
    *right_prefixes* on *template_obj*. Uses the inbound ACE set on the object.
    Returns (labels, sids, is_broad) — is_broad True when a well-known everyone-
    ish trustee (Authenticated Users / Domain Users / Everyone) can do it."""
    from adcontrol.paths import PathFinder
    pf = PathFinder(analyzer)
    labels: list[str] = []
    sids: list[str] = []
    is_broad = False
    seen: set[str] = set()
    for ace in template_obj.aces:
        if ace.right.startswith("DENY:"):
            continue
        if not any(ace.right.startswith(p) for p in right_prefixes):
            continue
        tsid = ace.trustee_sid
        if tsid in seen:
            continue
        seen.add(tsid)
        if R.is_broad_trustee(tsid):
            is_broad = True
        holder = store.by_sid(tsid)
        # Skip enrollment held only by Tier-0 principals (expected/admin).
        if holder is not None and pf.already_tier0(holder):
            continue
        label = holder.label if holder else (R.wellknown_name(tsid) or tsid)
        labels.append(label)
        sids.append(tsid)
    return labels, sids, is_broad


def analyze_adcs(store, analyzer, log=None) -> int:
    """Walk collected certificate templates and emit AdcsFinding records for the
    ESC1–ESC4 conditions. Returns the number of findings added. Idempotent-ish:
    clears any prior adcs_findings first."""
    log = log or (lambda m, l="info": None)
    store.adcs_findings = []
    templates = [o for o in store.objects.values()
                 if o.object_class == "pKICertificateTemplate"]
    if not templates:
        return 0

    added = 0
    for obj in templates:
        t = obj.extra.get("adcs_template")
        if t is None:
            continue   # attributes weren't captured (shouldn't happen post-collect)
        enrollers, enr_sids, enr_broad = _low_priv_enrollers(store, analyzer, obj)
        writers, wr_sids, wr_broad = _low_priv_writers(store, analyzer, obj)

        # ESC4 — a non-Tier-0 principal can rewrite the template object itself.
        if writers:
            store.adcs_findings.append(AdcsFinding(
                esc="ESC4", template=t.name or obj.label, template_dn=obj.dn,
                severity="high", enrollers=writers, enroller_sids=wr_sids,
                detail="Template object is writable by a non-privileged principal — "
                       "it can be reconfigured into an ESC1 template and abused.",
                reasons=["writable template object"]))
            added += 1

        # The enrollment-based ESCs require someone low-priv to be able to enroll.
        if not enrollers:
            continue
        no_approval = not t.manager_approval and t.ra_signatures == 0

        # ESC1 — enrollee supplies subject + auth EKU + no approval.
        if t.enrollee_supplies_subject and t.authentication and no_approval:
            store.adcs_findings.append(AdcsFinding(
                esc="ESC1", template=t.name or obj.label, template_dn=obj.dn,
                severity="high", enrollers=enrollers, enroller_sids=enr_sids,
                detail="Low-privileged principals can enroll and supply the subject "
                       "(SAN) on a client-auth template with no manager approval — "
                       "request a cert as any user (e.g. a Domain Admin).",
                reasons=["enrollee supplies subject", "client-auth EKU",
                         "no manager approval"] + (["Authenticated Users can enroll"]
                                                   if enr_broad else [])))
            added += 1

        # ESC2 — Any-Purpose EKU (or no EKU) + no approval.
        elif t.any_purpose and no_approval:
            store.adcs_findings.append(AdcsFinding(
                esc="ESC2", template=t.name or obj.label, template_dn=obj.dn,
                severity="high", enrollers=enrollers, enroller_sids=enr_sids,
                detail="Low-privileged principals can enroll a template with the "
                       "Any-Purpose EKU (or no EKU restriction) and no approval — "
                       "the issued cert can be used for client authentication.",
                reasons=["Any-Purpose / no EKU", "no manager approval"]))
            added += 1

        # ESC3 — Certificate Request Agent (enrollment agent) template.
        if t.enrollment_agent and no_approval:
            store.adcs_findings.append(AdcsFinding(
                esc="ESC3", template=t.name or obj.label, template_dn=obj.dn,
                severity="high", enrollers=enrollers, enroller_sids=enr_sids,
                detail="Low-privileged principals can enroll a Certificate Request "
                       "Agent template — mint enrollment-agent certs to request "
                       "certificates on behalf of other principals.",
                reasons=["Certificate-Request-Agent EKU", "no manager approval"]))
            added += 1

    # Sort by ESC id then template name for stable output.
    store.adcs_findings.sort(key=lambda f: (f.esc, f.template.lower()))
    log(f"[adcs] {added} ESC finding(s) across {len(templates)} template(s)", "info")
    return added


def findings_for_subject(store, subject) -> list:
    """AdcsFinding records where *subject* (directly or via a group) is one of the
    enrollers/controllers — i.e. ESC paths this principal can abuse. Matched by
    SID against enroller_sids, plus a broad-trustee fallback."""
    out = []
    findings = getattr(store, "adcs_findings", None) or []
    if not findings:
        return out
    from adcontrol.graph import MembershipGraph
    g = MembershipGraph(store)
    want = set(g.effective_sids(subject))
    for f in findings:
        if want & set(f.enroller_sids or []):
            out.append(f)
    return out
