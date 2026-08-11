"""
AD Certificate Services (ADCS) analysis — ESC misconfiguration detection.

Certificate templates and enrollment services live under the Configuration
naming context. A template is an AD object with a DACL (enrollment rights are
ACEs), so it flows through the same ObjectStore/ACE pipeline as everything else;
this module adds the ADCS-specific *interpretation* on top:

  * ``normalize_from_ldap`` / ``normalize_from_bh`` read the ESC-relevant
    template attributes into a common shape from either a live LDAP record or a
    BloodHound Properties dict.
  * ``analyze_adcs`` walks every collected template, works out who can enroll
    (or, for ESC4, who can reconfigure it), and emits :class:`AdcsFinding`
    records for every LDAP-derivable ESC condition:

      - **ESC1**  — low-priv can enroll, template lets the enrollee supply the
        subject (SAN), issues a client-auth cert, no manager approval / RA sig.
      - **ESC2**  — low-priv can enroll a template with the Any-Purpose EKU (or
        no EKU), no approval — a cert usable for anything incl. client auth.
      - **ESC3**  — low-priv can enroll a Certificate-Request-Agent (enrollment
        agent) template — mint on-behalf-of certs for other principals.
      - **ESC4**  — the template OBJECT is writable by a low-priv principal
        (GenericAll/Write/WriteDacl/WriteOwner/Owns) — they can flip it into
        ESC1 and enroll.
      - **ESC5**  — a low-priv principal has Write* control over a PKI
        infrastructure object (NTAuthCertificates, AIA, CDP, an OID object, or
        the Certificate-Templates/Enrollment-Services/Certification-Authorities
        containers) — enough to trust a rogue CA, redirect validation, or plant
        a malicious ESC13 OID-group link. See ``_analyze_pki_infra``.
      - **ESC9**  — template has ``CT_FLAG_NO_SECURITY_EXTENSION`` set (omits
        the SID security extension), allows client auth, low-priv can enroll.
      - **ESC13** — template's issuance policy OID is linked (via the OID
        object's ``msDS-OIDToGroupLink``) to an AD group; enrolling grants that
        group's SID in the resulting TGT. See ``store.oid_group_links``.
      - **ESC14** — an account's ``altSecurityIdentities`` contains a weakly
        specified explicit certificate mapping (no issuer+serial or public-key
        pin). See ``_analyze_weak_mappings``.
      - **ESC15** — Schema Version 1 template with enrollee-supplies-subject
        (CVE-2024-49019 "EKUwu" — arbitrary Application Policy injection);
        exploitable only if the CA is unpatched.
      - **ESC17** — same shape as ESC1 but for a Server-Authentication (or
        Any-Purpose/no-EKU) template — impersonate a *server* identity (e.g. an
        internal WSUS host) rather than a user.

  * ``_analyze_ca_config`` covers the CA-registry-derived ESCs — these are
    NOT LDAP attributes (confirmed by reading certipy-ad's own installed
    source: they come from ``CA.get_config_rrp()``, a Remote Registry
    Protocol read against the CA HOST itself, not the DC), so they only
    populate when the opt-in ``adcs_ca.collect_ca_config()`` plane ran first
    (needs SMB/RPC to each CA host — see adcs_ca.py's module docstring):

      - **ESC6**  — CA-wide ``EDITF_ATTRIBUTESUBJECTALTNAME2`` (enrollee can
        specify SAN via request attributes on ANY template this CA issues).
      - **ESC7**  — ManageCa/ManageCertificates on the CA's OWN security
        descriptor (registry ``Security`` value, a completely different
        access-mask vocabulary from AD's ACCESS_MASK) granted to a non-Tier-0
        principal.
      - **ESC8**  — Web Enrollment (``/certsrv/``) reachable over plain HTTP
        — an exposure indicator only (an HTTP GET), not the NTLM-relay attack
        itself, which needs live coercion+relay tooling this doesn't do.
      - **ESC11** — CA doesn't enforce RPC packet-privacy
        (``IF_ENFORCEENCRYPTICERTREQUEST`` unset) — relay-to-RPC exposure,
        same shape as ESC8 on a different transport.
      - **ESC16** — CA globally omits the SID security extension
        (``DisableExtensionList`` contains ``szOID_NTDS_CA_SECURITY_EXT``) —
        equivalent to ESC9 on every template this CA issues at once.

    Deliberately NOT implemented — genuinely not enumerable, not just
    "not gotten to yet": **ESC10** (Schannel ``CertificateMappingMethods``)
    is a DC-local registry key Certipy itself doesn't detect either (needs
    local-admin-level access to every DC, not the CA). **ESC12** (YubiHSM2
    host software vulnerability) isn't an AD/PKI misconfiguration at all —
    Certipy explicitly says so too.

The "low-priv can enroll/control" test reuses the store's ACEs and the same
well-known-broad-trustee logic as the rest of the tool: an enrollment right
held by Authenticated Users / Domain Users / Everyone (or by any non-Tier-0
principal) is what makes a template abusable.
"""

from __future__ import annotations

from adcontrol.model import AdcsFinding
from adcontrol import rights as R
from adcontrol import adcs_ca

# --- template flag bit values (MS-CRTD) ------------------------------------
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001   # msPKI-Certificate-Name-Flag
EF_PEND_ALL_REQUESTS = 0x00000002                # msPKI-Enrollment-Flag: manager approval
EF_NO_SECURITY_EXTENSION = 0x00080000            # msPKI-Enrollment-Flag: CT_FLAG_NO_SECURITY_EXTENSION (ESC9)
# NB: manager-approval bit is 0x2 in msPKI-Enrollment-Flag (CT_FLAG_PEND_ALL_REQUESTS).

# Full MS-CRTD flag-bit tables + EKU OID friendly names, for the "full
# certipy-style template dump" in the GUI/report — reused directly from the
# `certipy-ad` package (installed alongside this tool for exactly this
# purpose) rather than re-transcribed by hand, so the bit tables can't drift
# from upstream and can't contain a transcription error. Optional: if
# certipy-ad isn't installed, the ESC detection above still works unaffected
# (it only uses the couple of bits defined locally); only the rich "every set
# flag, decoded" display and EKU-OID-to-name lookup degrade to showing raw
# hex/OIDs instead of names.
try:
    from certipy.lib.constants import (
        CertificateNameFlag as _CertNameFlagEnum,
        EnrollmentFlag as _EnrollFlagEnum,
        PrivateKeyFlag as _PrivKeyFlagEnum,
        OID_TO_STR_MAP as _OID_NAMES,
    )
except Exception:
    _CertNameFlagEnum = _EnrollFlagEnum = _PrivKeyFlagEnum = None
    _OID_NAMES = {}


def eku_name(oid: str) -> str:
    """Friendly EKU/application-policy name for an OID, or the OID itself if
    unknown (e.g. certipy-ad isn't installed, or it's a non-standard OID)."""
    return _OID_NAMES.get(oid, oid)


def _decode_flags(value: int, flag_enum) -> list[str]:
    """Every named bit set in *value*, sorted, using a certipy IntFlag enum.
    Empty list if the enum isn't available (certipy-ad not installed) or no
    bits are set — callers should fall back to showing the raw hex value."""
    if not value or flag_enum is None:
        return []
    try:
        return sorted(f.name for f in flag_enum if f.name != "NONE" and value & f.value)
    except Exception:
        return []

# EKUs (OIDs) that make an issued cert usable for domain authentication.
_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",        # Client Authentication
    "1.3.6.1.5.2.3.4",          # PKINIT Client Authentication
    "1.3.6.1.4.1.311.20.2.2",   # Smart Card Logon
    "2.5.29.37.0",              # Any Purpose
}
_ANY_PURPOSE_EKU = "2.5.29.37.0"
_ENROLLMENT_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"   # Certificate Request Agent
_SERVER_AUTH_EKU = "1.3.6.1.5.5.7.3.1"             # Server Authentication (ESC17)

# Enrollment right names our SD parser / BH importer produce.
_ENROLL_RIGHTS = ("Certificate-Enrollment", "Certificate-AutoEnrollment",
                  "Enroll", "AutoEnroll")
# Rights that mean "can reconfigure the whole object" (ESC4) — same shape used
# for PKI-infra object control (ESC5). Deliberately does NOT include the bare
# "WriteProperty" prefix: sddl.py names an OBJECT-SCOPED WriteProperty ACE
# "WriteProperty:<attr>" (e.g. "WriteProperty:Enroll") for a grant on a single
# specific attribute — a prefix match on bare "WriteProperty" would wrongly
# catch that as "can reconfigure the template," when in fact you'd need write
# access to SEVERAL specific attributes (msPKI-Certificate-Name-Flag,
# msPKI-Enrollment-Flag, the DACL itself, ...) to actually flip a template
# into an ESC1 shape — a single narrow attribute grant isn't enough. Real
# Certipy makes exactly this distinction too (its own `template_has_
# vulnerable_acl` only counts WriteProperty when the object-type GUID is the
# NULL GUID, i.e. unscoped/all-properties) — sddl.py already names THAT case
# distinctly as "WriteAllProperties" (no object-type GUID, see
# _named_rights_for_ace), which IS in this tuple. Bug caught on real GOAD
# data: Domain Users held only "WriteProperty:Enroll" (a narrow, unrelated
# attribute grant) on ~8 unpublished built-in templates (Basic EFS, Computer,
# IPSec, ...) and was wrongly flagged ESC4 on all of them before this fix.
_TEMPLATE_WRITE_RIGHTS = ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
                          "Owns", "WriteAllProperties")


class Template:
    """Normalized certificate-template view used for ESC analysis."""

    __slots__ = ("dn", "name", "enrollee_supplies_subject", "manager_approval",
                 "ra_signatures", "ekus", "authentication", "schema_version",
                 "no_security_extension", "cas", "issuance_policies",
                 "name_flag_raw", "enrollment_flag_raw", "private_key_flag_raw")

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
        self.issuance_policies: set[str] = set()   # OID strings (ESC13)
        # Raw msPKI-*-Flag integers, for the full certipy-style flag dump
        # (_decode_flags). Only populated on the live-LDAP path — BloodHound's
        # Properties expose pre-derived booleans, not the raw bitmask, so
        # these stay 0 (decode degrades to empty list) on an offline import.
        self.name_flag_raw = 0
        self.enrollment_flag_raw = 0
        self.private_key_flag_raw = 0

    @property
    def any_purpose(self) -> bool:
        return _ANY_PURPOSE_EKU in self.ekus or not self.ekus

    @property
    def enrollment_agent(self) -> bool:
        return _ENROLLMENT_AGENT_EKU in self.ekus

    @property
    def server_authentication(self) -> bool:
        """Issues a cert usable for TLS server identity (ESC17) — an explicit
        Server-Authentication EKU, or the same any-purpose/no-EKU cases that
        make ``authentication`` True for client auth."""
        return _SERVER_AUTH_EKU in self.ekus or self.any_purpose


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
    t.name_flag_raw = name_flag
    t.enrollee_supplies_subject = bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    enroll_flag = _as_int(first(rec, "msPKI-Enrollment-Flag"))
    t.enrollment_flag_raw = enroll_flag
    t.manager_approval = bool(enroll_flag & EF_PEND_ALL_REQUESTS)
    t.no_security_extension = bool(enroll_flag & EF_NO_SECURITY_EXTENSION)
    t.private_key_flag_raw = _as_int(first(rec, "msPKI-Private-Key-Flag"))
    t.ra_signatures = _as_int(first(rec, "msPKI-RA-Signature"))
    t.schema_version = _as_int(first(rec, "msPKI-Template-Schema-Version"), 1)
    ekus = rec.get("pKIExtendedKeyUsage") or []
    app_pol = rec.get("msPKI-Certificate-Application-Policy") or []
    t.ekus = _eku_set(ekus, app_pol)
    t.authentication = bool(t.ekus & _AUTH_EKUS) or not t.ekus
    t.issuance_policies = _eku_set(rec.get("msPKI-Certificate-Policy"))
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
    # Issuance-policy OIDs (ESC13). BHCE's exact property key for this hasn't
    # been verified against a live ADCS-enabled BHCE export in this codebase
    # (no such sample was available when this was added) — check every
    # plausible key defensively rather than picking one and silently missing
    # the data if it's actually named differently.
    t.issuance_policies = _eku_set(
        props.get("certificatepolicy"), props.get("certificatepolicies"),
        props.get("issuancepolicies"))
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
        # Tier-0 check FIRST, directly on the raw SID's well-known RID/SID
        # pattern (rights.is_builtin_admin_trustee — the same check
        # analyze.py's _is_builtin_noise uses) — this works even when the
        # trustee object itself was never collected. That's the common case
        # for Enterprise/Schema Admins (RID 519/518): those groups live ONLY
        # in the FOREST ROOT domain's NC, so a scan of a child domain never
        # collects them as objects, and the old code — which only checked
        # already_tier0() when `store.by_sid(tsid)` resolved — silently
        # treated them as non-Tier-0 abusers. Confirmed against a real
        # domain's actual `certipy find` output: every template's Full
        # Control/WriteDacl/WriteOwner was RID 512/519 only (zero real ESC4),
        # while adcontrol was flagging "tons of ESC4" — this was why.
        # already_tier0() (object-resolved, catches inherited Tier-0 via
        # nested group membership) still runs as a second check when the SID
        # DOES resolve to a collected object.
        if R.is_builtin_admin_trustee(tsid):
            continue
        holder = store.by_sid(tsid)
        if holder is not None and pf.already_tier0(holder):
            continue
        if R.is_broad_trustee(tsid):
            is_broad = True
        label = holder.label if holder else (R.wellknown_name(tsid) or tsid)
        labels.append(label)
        sids.append(tsid)
    return labels, sids, is_broad


def published_by(store, obj) -> list[str]:
    """CA labels that publish (enable) this template — cross-referenced from
    each collected CA's own ``certificateTemplates`` attribute (a list of
    template CNs, not DNs) against this template's own ``cn`` (not its
    possibly-different displayName). Empty if the template exists in AD but
    isn't actually issuable by any collected CA — real Certipy's own
    "Enabled" field is exactly this: ``enabled = cas is not None and
    len(cas) > 0`` (confirmed by reading certipy-ad's source, since this gate
    matters for correctness, not just display — see ``_has_publication_data``)."""
    my_cn = (obj.extra.get("cn") or obj.name or "").lower()
    return sorted(
        ca.label for ca in store.objects.values()
        if ca.object_class == "pKIEnrollmentService"
        and my_cn in {c.lower() for c in (ca.extra.get("published_templates") or [])}
    )


def _has_publication_data(store) -> bool:
    """True if at least one collected CA actually carries a non-empty
    certificateTemplates list, i.e. there's real data to gate "enabled" on.
    False when no CA was collected at all, or CAs were collected but this
    specific cross-reference wasn't populated (currently only the live-LDAP
    path populates ``published_templates`` — a BloodHound import doesn't, no
    real ADCS-enabled BHCE export was available this session to confirm the
    CA node's property key for its published-template list). Gating "enabled"
    when we DON'T actually have publication data would silently suppress
    every enrollment-based ESC finding for the wrong reason (missing data,
    not "genuinely unpublished") — so the gate only applies when we can
    actually tell the difference."""
    return any(
        ca.object_class == "pKIEnrollmentService" and ca.extra.get("published_templates")
        for ca in store.objects.values()
    )


def analyze_adcs(store, analyzer, log=None) -> int:
    """Walk collected certificate templates and PKI-infra/account data and emit
    AdcsFinding records for every LDAP-derivable ESC condition (see module
    docstring for the full list and what's deliberately excluded). Returns the
    number of findings added. Idempotent-ish: clears any prior adcs_findings
    first. Template-based checks (ESC1/2/3/4/9/13/15/17) are skipped if no
    templates were collected, but ESC5 (PKI-infra ACLs) and ESC14 (weak
    altSecurityIdentities) run regardless — neither depends on templates."""
    log = log or (lambda m, l="info": None)
    store.adcs_findings = []
    from adcontrol.paths import PathFinder
    pf = PathFinder(analyzer)
    templates = [o for o in store.objects.values()
                 if o.object_class == "pKICertificateTemplate"]
    gate_on_enabled = _has_publication_data(store)

    added = 0
    for obj in templates:
        t = obj.extra.get("adcs_template")
        if t is None:
            continue   # attributes weren't captured (shouldn't happen post-collect)
        enrollers, enr_sids, enr_broad = _low_priv_enrollers(store, analyzer, obj)
        writers, wr_sids, wr_broad = _low_priv_writers(store, analyzer, obj)

        # ESC4 — a non-Tier-0 principal can rewrite the template object itself.
        # NOT gated on "enabled": real Certipy checks this unconditionally too
        # (template ownership/ACL control doesn't need the template to be
        # currently published — an attacker with WriteDacl could reconfigure
        # it AND get a CA to publish it later, e.g. via ESC7 Manage-CA).
        if writers:
            store.adcs_findings.append(AdcsFinding(
                esc="ESC4", template=t.name or obj.label, template_dn=obj.dn,
                severity="high", enrollers=writers, enroller_sids=wr_sids,
                detail="Template object is writable by a non-privileged principal — "
                       "it can be reconfigured into an ESC1 template and abused.",
                reasons=["writable template object"]))
            added += 1

        # The enrollment-based ESCs (everything below) require someone
        # low-priv to be able to enroll, AND — matching real Certipy's own
        # `is_enabled and user_can_enroll` precondition — the template must
        # actually be published by a CA. A template that exists in AD but
        # isn't published anywhere can't actually be issued, so it isn't a
        # live finding (only checked when we HAVE real publication data —
        # see _has_publication_data).
        if not enrollers:
            continue
        if gate_on_enabled and not published_by(store, obj):
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

        # ESC9 — no SID security extension + client-auth EKU. Doesn't itself
        # require "no approval": the omitted extension is what matters, not the
        # issuance gate (unlike ESC1/2/3/17, Certipy's own ESC9 precondition
        # list doesn't include manager-approval/RA-signature at all).
        if t.no_security_extension and t.authentication:
            store.adcs_findings.append(AdcsFinding(
                esc="ESC9", template=t.name or obj.label, template_dn=obj.dn,
                severity="medium", enrollers=enrollers, enroller_sids=enr_sids,
                detail="Template omits the SID security extension on issued certs "
                       "(CT_FLAG_NO_SECURITY_EXTENSION) and allows client "
                       "authentication — combined with UPN manipulation on a "
                       "GenericWrite-able account, or with ESC6/16, this maps a "
                       "cert to an arbitrary target account.",
                reasons=["NoSecurityExtension", "client-auth EKU",
                         "exploitability depends on DC StrongCertificateBindingEnforcement"]))
            added += 1

        # ESC13 — issuance policy OID linked (msDS-OIDToGroupLink) to an AD
        # group; enrolling adds that group's SID to the resulting TGT.
        if t.authentication and t.issuance_policies and store.oid_group_links:
            for oid in sorted(t.issuance_policies):
                group_dn = store.oid_group_links.get(oid)
                if not group_dn:
                    continue
                group = store.by_dn(group_dn)
                if group is not None and pf.already_tier0(group):
                    continue   # linked to an already-expected admin group
                group_label = group.label if group is not None else group_dn
                store.adcs_findings.append(AdcsFinding(
                    esc="ESC13", template=t.name or obj.label, template_dn=obj.dn,
                    severity="high", enrollers=enrollers, enroller_sids=enr_sids,
                    detail=f"Template's issuance policy is linked (msDS-OIDToGroupLink) "
                           f"to group '{group_label}' — enrolling grants that group's SID "
                           f"in the resulting Kerberos TGT, regardless of AD group membership.",
                    reasons=[f"issuance policy linked to group '{group_label}'",
                             "client-auth EKU"]))
                added += 1

        # ESC15 (CVE-2024-49019 "EKUwu") — Schema V1 template with
        # enrollee-supplies-subject lets an unpatched CA accept an
        # attacker-injected Application Policy (e.g. Client Authentication or
        # Certificate Request Agent) regardless of the template's own EKUs.
        if t.schema_version == 1 and t.enrollee_supplies_subject:
            store.adcs_findings.append(AdcsFinding(
                esc="ESC15", template=t.name or obj.label, template_dn=obj.dn,
                severity="medium", enrollers=enrollers, enroller_sids=enr_sids,
                detail="Schema Version 1 template with enrollee-supplies-subject — on "
                       "a CA unpatched for CVE-2024-49019 ('EKUwu'), an enrollee can "
                       "inject arbitrary Application Policies (e.g. Client "
                       "Authentication or Certificate Request Agent) not defined by "
                       "the template's own EKUs.",
                reasons=["Schema Version 1", "enrollee supplies subject",
                         "only exploitable if the CA is unpatched (Nov 2024 update)"]))
            added += 1

        # ESC17 — same shape as ESC1 but for server-authentication (or
        # any-purpose/no-EKU) templates: impersonate a *server* identity.
        if t.enrollee_supplies_subject and t.server_authentication and no_approval:
            store.adcs_findings.append(AdcsFinding(
                esc="ESC17", template=t.name or obj.label, template_dn=obj.dn,
                severity="high", enrollers=enrollers, enroller_sids=enr_sids,
                detail="Low-privileged principals can enroll and supply the subject "
                       "(SAN) on a server-auth template with no manager approval — "
                       "request a cert impersonating any server (e.g. an internal "
                       "WSUS host) for relay or malicious-update attacks.",
                reasons=["enrollee supplies subject", "server-auth EKU",
                         "no manager approval"]))
            added += 1

    added += _analyze_pki_infra(store, analyzer, log)
    added += _analyze_weak_mappings(store, analyzer, log)
    added += _analyze_ca_config(store, analyzer, log)

    # Sort by ESC id then template name for stable output.
    store.adcs_findings.sort(key=lambda f: (f.esc, f.template.lower()))
    log(f"[adcs] {added} ESC finding(s) across {len(templates)} template(s) "
       f"(+ PKI-infra objects / accounts for ESC5/ESC14)", "info")
    return added


# Names of the PKI-infra containers/objects worth flagging for ESC5, mapped to
# a severity: NTAuthCertificates control lets you trust a rogue CA for domain
# auth outright (high, same blast radius as owning a CA); the OID container
# lets you fabricate ESC13 group links (high); AIA/CDP/the template & CA
# containers are lower-impact (denial/redirection/indirect) but still worth a
# finding (medium). Matched case-insensitively against the object's CN/name.
_PKI_INFRA_SEVERITY = {
    "ntauthcertificates": "high",
    "oid": "high",
    "certificate templates": "medium",
    "enrollment services": "medium",
    "certification authorities": "medium",
    "aia": "medium",
    "cdp": "medium",
    "kra": "medium",
}


def _analyze_pki_infra(store, analyzer, log) -> int:
    """ESC5 — Write* control over a PKI infrastructure AD object (not a
    template, not a CA/enrollment-service object — those are ESC4/handled
    elsewhere). Identified by DN: anything directly under the PKI Services
    container in the Configuration NC that ISN'T a template or enrollment
    service. Certipy itself doesn't detect this (it requires auditing
    miscellaneous PKI object ACLs); this reuses the same generic ACL data
    every other object in the store already carries."""
    added = 0
    for obj in store.objects.values():
        if ",CN=PUBLIC KEY SERVICES,CN=SERVICES," not in obj.dn.upper():
            continue
        if obj.object_class in ("pKICertificateTemplate", "pKIEnrollmentService"):
            continue   # covered by ESC4 / not a generic infra object
        writers, wr_sids, wr_broad = _actors_with(store, analyzer, obj, _TEMPLATE_WRITE_RIGHTS)
        # Cert Publishers (RID 517) — and the other "well-known privileged but
        # not full-admin" groups — legitimately need write access to these
        # SPECIFIC containers by Windows' own default ACL: Cert Publishers
        # exists precisely so a CA machine account can publish its own
        # cert/CRL under CDP/AIA. _actors_with's Tier-0 gate
        # (is_builtin_admin_trustee) doesn't cover 517 — it's not a
        # full-admin group — so filter it here specifically, where "expected"
        # is unambiguous (unlike a certificate TEMPLATE's ACL, where the same
        # group holding control would be unusual and still worth flagging —
        # this filter deliberately isn't applied to the shared
        # _actors_with()/ESC4 path). Bug caught on real GOAD data: RID 517,
        # unresolved as an object (forest-root-only group, same class of gap
        # as the Enterprise Admins ESC4 fix), was flagging AIA/CDP/CA
        # containers on every real deployment.
        kept = [(l, s) for l, s in zip(writers, wr_sids) if not R.is_wellknown_privileged_group(s)]
        writers = [l for l, s in kept]
        wr_sids = [s for l, s in kept]
        if not writers:
            continue
        sev = _PKI_INFRA_SEVERITY.get(obj.label.lower(), "medium")
        store.adcs_findings.append(AdcsFinding(
            esc="ESC5", template=obj.label, template_dn=obj.dn,
            severity=sev, enrollers=writers, enroller_sids=wr_sids,
            detail=f"'{obj.label}' is a PKI infrastructure object (Configuration NC) "
                   f"writable by a non-privileged principal — depending on which "
                   f"object, this can trust a rogue CA for domain authentication, "
                   f"redirect certificate validation, or plant a malicious ESC13 "
                   f"issuance-policy group link.",
            reasons=["writable PKI infrastructure object"]))
        added += 1
    return added


def _analyze_ca_config(store, analyzer, log) -> int:
    """ESC6/ESC7/ESC8/ESC11/ESC16 — CA-registry-derived findings. Requires
    ``adcs_ca.collect_ca_config()`` to have run first (opt-in, needs SMB/RPC
    to each CA host, not just the DC); degrades to nothing (not an error) for
    any CA where ``ca.extra['ca_config']`` is absent — matches the rest of
    this module's best-effort philosophy. Not gated on template "enabled",
    since these are CA-wide config, not per-template."""
    added = 0
    from adcontrol.paths import PathFinder
    pf = PathFinder(analyzer)
    for ca in store.objects.values():
        if ca.object_class != "pKIEnrollmentService":
            continue
        cfg = ca.extra.get("ca_config")
        if not cfg:
            continue   # adcs_ca.collect_ca_config() never ran for this CA at all
        ca_label = ca.extra.get("cn") or ca.name or ca.label
        # Registry (ESC6/7/11/16) and web-enrollment (ESC8) are collected
        # independently (one can fail — e.g. Remote Registry not running —
        # while the other succeeds) so they're gated independently here too.
        registry_ok = cfg.get("registry_collected", True)  # True for pre-split cfg dicts

        # ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2: CA-wide "enrollee can specify SAN".
        if registry_ok and cfg["edit_flags"] & adcs_ca.EDITF_ATTRIBUTESUBJECTALTNAME2:
            store.adcs_findings.append(AdcsFinding(
                esc="ESC6", template=ca_label, template_dn=ca.dn, ca=ca_label,
                severity="medium",
                detail="CA allows enrollees to specify a SAN via request attributes "
                       "(EDITF_ATTRIBUTESUBJECTALTNAME2) on ANY template it issues from "
                       "— combined with ESC9 or ESC16 (no SID security extension), this "
                       "allows impersonation even on a fully patched domain.",
                reasons=["EDITF_ATTRIBUTESUBJECTALTNAME2 set on the CA",
                         "exploitable when combined with ESC9 or ESC16"]))
            added += 1

        # ESC7 — ManageCa/ManageCertificates granted to a non-Tier-0 principal.
        # Same Tier-0-first-on-raw-SID check as _actors_with (the ESC4 fix) —
        # a CA-level admin ACE is just as likely to name a cross-domain
        # built-in group (Enterprise Admins) that wasn't collected as an
        # object in a child-domain-scoped scan.
        holders, holder_sids = [], []
        for sid, names in (cfg.get("security_aces", []) if registry_ok else []):
            if not ({"ManageCa", "ManageCertificates"} & set(names)):
                continue
            if R.is_builtin_admin_trustee(sid):
                continue
            holder = store.by_sid(sid)
            if holder is not None and pf.already_tier0(holder):
                continue
            label = holder.label if holder else (R.wellknown_name(sid) or sid)
            holders.append(f"{label} ({'/'.join(n for n in names if n != 'Enroll')})")
            holder_sids.append(sid)
        if holders:
            store.adcs_findings.append(AdcsFinding(
                esc="ESC7", template=ca_label, template_dn=ca.dn, ca=ca_label,
                severity="high", enrollers=holders, enroller_sids=holder_sids,
                detail="Non-privileged principal(s) hold ManageCa/ManageCertificates on "
                       "the CA — can enable a dangerous template (e.g. SubCA), submit a "
                       "request, then approve their own pending request, leading to full "
                       "domain compromise.",
                reasons=["ManageCa/ManageCertificates granted to a non-Tier-0 principal"]))
            added += 1

        # ESC8 — Web Enrollment reachable over plain HTTP (exposure only —
        # exploitation needs live NTLM coercion+relay, not built here).
        web = cfg.get("web_enrollment") or {}
        if web.get("http") is True:
            store.adcs_findings.append(AdcsFinding(
                esc="ESC8", template=ca_label, template_dn=ca.dn, ca=ca_label,
                severity="high",
                detail="CA's Web Enrollment endpoint (/certsrv/) is reachable over plain "
                       "HTTP — vulnerable to NTLM relay: coerce a privileged account's "
                       "authentication and relay it here to request a certificate as "
                       "them. This only confirms exposure; exploitation needs separate "
                       "relay tooling (e.g. ntlmrelayx.py), not built into adcontrol.",
                reasons=["Web Enrollment reachable over HTTP", "NTLM relay target"]))
            added += 1

        # ESC11 — ICPR/RPC requests not required to be encrypted.
        if registry_ok and not (cfg["interface_flags"] & adcs_ca.IF_ENFORCEENCRYPTICERTREQUEST):
            store.adcs_findings.append(AdcsFinding(
                esc="ESC11", template=ca_label, template_dn=ca.dn, ca=ca_label,
                severity="medium",
                detail="CA does not enforce encryption (RPC_C_AUTHN_LEVEL_PKT_PRIVACY) "
                       "for ICPR/RPC certificate requests — vulnerable to NTLM relay "
                       "against the CA's RPC interface (same impact class as ESC8, "
                       "different transport).",
                reasons=["IF_ENFORCEENCRYPTICERTREQUEST not set"]))
            added += 1

        # ESC16 — SID security extension globally disabled at the CA.
        if registry_ok and adcs_ca.SZOID_NTDS_CA_SECURITY_EXT in (cfg.get("disabled_extensions") or []):
            store.adcs_findings.append(AdcsFinding(
                esc="ESC16", template=ca_label, template_dn=ca.dn, ca=ca_label,
                severity="medium",
                detail="CA is configured to omit the SID security extension from EVERY "
                       "certificate it issues (DisableExtensionList) — equivalent to "
                       "ESC9 on every template published here at once; exploitable via "
                       "UPN manipulation (weak DC binding mode) or combined with ESC6.",
                reasons=["szOID_NTDS_CA_SECURITY_EXT in DisableExtensionList"]))
            added += 1
    return added


# altSecurityIdentities mapping types considered strong (tie to a specific
# cert instance or key, not an easily-replicated field) vs everything else,
# which is treated as weak per the ESC14 write-up's guidance.
_STRONG_MAPPING_MARKERS = ("<SR>", "<SHA1-PUKEY>", "<SKI>")


def _classify_mapping(entry: str) -> bool:
    """True if *entry* (an altSecurityIdentities value) uses a strong mapping
    format. Case-insensitive on the marker tags Windows itself uses."""
    up = entry.upper()
    return any(m in up for m in _STRONG_MAPPING_MARKERS)


def _analyze_weak_mappings(store, analyzer, log) -> int:
    """ESC14 — a user/computer account has a weakly specified explicit
    certificate mapping in altSecurityIdentities (e.g. Subject-CN-only or a
    bare RFC822 email, with no issuer+serial or public-key pin) — anyone who
    can obtain or craft a certificate matching that weak criterion can
    authenticate as the account. Certipy doesn't auto-detect this (weakness is
    a judgment call on the mapping string); this applies the wiki's own
    strong-vs-weak marker guidance. Severity reflects whether the AFFECTED
    account is itself Tier-0 (impersonating it is more valuable) — checked via
    EFFECTIVE group SIDs (graph.effective_sids), not the account's own SID:
    the account's own SID is almost never one of the built-in admin GROUP
    SIDs/RIDs (not even the real 'Administrator' user, RID 500, which isn't in
    that RID set — only its containing groups like Domain Admins are), so a
    raw-SID check would silently never fire "high" for a genuinely privileged
    user account."""
    added = 0
    for obj in store.objects.values():
        if obj.object_class not in ("user", "computer"):
            continue
        entries = obj.extra.get("alt_security_identities") or []
        weak = [e for e in entries if not _classify_mapping(e)]
        if not weak:
            continue
        is_tier0 = any(R.is_builtin_admin_trustee(s) for s in analyzer.graph.effective_sids(obj))
        store.adcs_findings.append(AdcsFinding(
            esc="ESC14", template=obj.label, template_dn=obj.dn,
            severity="high" if is_tier0 else "medium",
            detail=f"'{obj.label}' has a weakly specified explicit certificate mapping "
                   f"in altSecurityIdentities ({'; '.join(weak)}) — lacks an issuer+serial "
                   f"or public-key pin, so a certificate obtained or crafted elsewhere "
                   f"matching this loose criterion (e.g. Subject CN only) can "
                   f"authenticate as this account.",
            reasons=weak))
        added += 1
    return added


def template_detail_for(store, subject) -> dict:
    """Full certipy-`find`-style dump for a certificate-template subject: every
    decoded flag, EKU, issuance policy, publishing CA, and — critically — the
    specific ESC findings for THIS template with their reasons, so the GUI/
    report can show not just "ESC1" but exactly which conditions matched.
    Returns ``{}`` for non-template subjects."""
    if subject.object_class != "pKICertificateTemplate":
        return {}
    t = subject.extra.get("adcs_template")
    if t is None:
        return {}

    name_flags = _decode_flags(t.name_flag_raw, _CertNameFlagEnum)
    enrollment_flags = _decode_flags(t.enrollment_flag_raw, _EnrollFlagEnum)
    private_key_flags = _decode_flags(t.private_key_flag_raw, _PrivKeyFlagEnum)

    cas = published_by(store, subject)
    has_pub_data = _has_publication_data(store)

    findings = [f for f in (store.adcs_findings or []) if f.template_dn == subject.dn]

    return {
        "name": t.name or subject.label,
        "dn": subject.dn,
        "schema_version": t.schema_version,
        "published_by": cas,
        # "enabled" mirrors real Certipy's own definition (published by >=1
        # CA). None (not True/False) when we don't actually have publication
        # data to judge by (see _has_publication_data) — the GUI shows this
        # as "unknown" rather than a misleading "disabled".
        "enabled": (bool(cas) if has_pub_data else None),
        "ekus": sorted(eku_name(o) for o in t.ekus) if t.ekus else [],
        "any_purpose": t.any_purpose,
        "enrollment_agent": t.enrollment_agent,
        "server_authentication": t.server_authentication,
        "enrollee_supplies_subject": t.enrollee_supplies_subject,
        "manager_approval": t.manager_approval,
        "authorized_signatures_required": t.ra_signatures,
        "no_security_extension": t.no_security_extension,
        "name_flags": name_flags, "name_flag_raw": t.name_flag_raw,
        "enrollment_flags": enrollment_flags, "enrollment_flag_raw": t.enrollment_flag_raw,
        "private_key_flags": private_key_flags, "private_key_flag_raw": t.private_key_flag_raw,
        "issuance_policies": [
            {"oid": oid, "name": eku_name(oid),
             "linked_group": (lambda g: g.label if g else None)(
                 store.by_dn(store.oid_group_links.get(oid, "")))}
            for oid in sorted(t.issuance_policies)
        ],
        "vulnerabilities": [
            {"esc": f.esc, "severity": f.severity, "detail": f.detail, "reasons": f.reasons}
            for f in findings
        ],
        "flags_decoded": _CertNameFlagEnum is not None,   # tells the GUI whether
        # raw hex or named flags are being shown (certipy-ad not installed = hex).
    }


def ca_detail_for(store, subject) -> dict:
    """Registry-derived CA config dump (ESC6/7/8/11/16) for a CA subject.
    ``{}`` for non-CA subjects. ``collected: False`` (rather than absent
    fields) when ``adcs_ca.collect_ca_config()`` never ran at all for this CA
    — the GUI uses this to show a clear "run --adcs-ca-config" hint instead
    of looking like the CA is simply clean. Registry (ESC6/7/11/16) and
    web-enrollment (ESC8) are collected independently and can fail
    independently (Remote Registry not running is common and unrelated to
    whether the CA answers HTTP) — ``registry_collected`` distinguishes which
    half of ``collected: True`` actually has real data."""
    if subject.object_class != "pKIEnrollmentService":
        return {}
    findings = [
        {"esc": f.esc, "severity": f.severity, "detail": f.detail, "reasons": f.reasons}
        for f in (store.adcs_findings or []) if f.template_dn == subject.dn
    ]
    cfg = subject.extra.get("ca_config")
    if cfg is None:
        return {"collected": False, "registry_collected": False, "vulnerabilities": findings}

    registry_ok = cfg.get("registry_collected", True)
    security_aces = []
    for sid, names in (cfg.get("security_aces", []) if registry_ok else []):
        holder = store.by_sid(sid)
        security_aces.append({
            "label": holder.label if holder else (R.wellknown_name(sid) or sid),
            "rights": names,
        })

    return {
        "collected": True,
        "registry_collected": registry_ok,
        "published_templates": sorted(subject.extra.get("published_templates") or []),
        "edit_flags": cfg.get("edit_flags", 0),
        "san_via_request_attributes": bool(cfg.get("edit_flags", 0) & adcs_ca.EDITF_ATTRIBUTESUBJECTALTNAME2),
        "interface_flags": cfg.get("interface_flags", 0),
        "enforce_encryption": bool(cfg.get("interface_flags", 0) & adcs_ca.IF_ENFORCEENCRYPTICERTREQUEST),
        "disabled_extensions": cfg.get("disabled_extensions", []),
        "security_extension_disabled": adcs_ca.SZOID_NTDS_CA_SECURITY_EXT in (cfg.get("disabled_extensions") or []),
        "web_enrollment_http": (cfg.get("web_enrollment") or {}).get("http"),
        "security_owner": cfg.get("security_owner", ""),
        "security_aces": security_aces,
        "vulnerabilities": findings,
    }


def findings_for_subject(store, subject) -> list:
    """AdcsFinding records relevant to *subject* — either as an abuser (they,
    directly or via a group, are one of the enrollers/controllers listed on
    the finding) or as the AFFECTED object itself (``template_dn`` IS this
    subject's own DN — the shape ESC5/ESC14 findings use, since neither has a
    meaningful "enroller" list: ESC5 is about who can rewrite a PKI-infra
    object, ESC14 is about an account's own weak cert mapping, not who can
    enroll something)."""
    out = []
    findings = getattr(store, "adcs_findings", None) or []
    if not findings:
        return out
    from adcontrol.graph import MembershipGraph
    g = MembershipGraph(store)
    want = set(g.effective_sids(subject))
    for f in findings:
        if (want & set(f.enroller_sids or [])) or f.template_dn == subject.dn:
            out.append(f)
    return out
