"""
Drive an :class:`~adcontrol.connection.LdapClient` to pull every relevant AD
object — with its ``nTSecurityDescriptor`` — into an :class:`~adcontrol.model.ObjectStore`.

Also collects the schema's ``attributeSchema`` / ``rightsGuid`` maps so that
object-type GUIDs on ACEs can be shown by name, and reads the domain SID.

Everything downstream reads the store, never LDAP — so an offline parser can
target the same store shape (see model.py) to reuse the whole pipeline.
"""

from __future__ import annotations

import datetime

from adcontrol import sddl
from adcontrol.model import ObjectStore, RawObject

# Attributes we pull for the main object sweep.
_ATTRS = [
    "distinguishedName", "objectSid", "objectGUID", "sAMAccountName", "cn",
    "name", "displayName", "objectClass", "nTSecurityDescriptor",
    "member", "memberOf", "gPLink", "adminCount", "userAccountControl",
    "servicePrincipalName", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "operatingSystem", "gPCFileSysPath", "dNSHostName",
    # gMSA password-retrieval principals (an SD blob, parsed like nTSecurityDescriptor).
    "msDS-GroupMSAMembership", "sAMAccountType",
    # delegation / staleness / creds-in-description (analysis extras).
    "msDS-AllowedToDelegateTo", "sIDHistory", "description",
    "pwdLastSet", "lastLogonTimestamp",
    # ADCS certificate-template attributes (ESC1-ESC3 conditions).
    "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
    "msPKI-Template-Schema-Version", "pKIExtendedKeyUsage",
    "msPKI-Certificate-Application-Policy",
]

# One filter that captures every principal + container we care about controlling.
# Includes (group) managed service accounts — they are principals that can be
# local admin / hold SPNs / be granted rights, and their msDS-GroupMSAMembership
# SD is a first-class control edge (who can retrieve the gMSA password).
_MAIN_FILTER = (
    "(|(objectClass=user)(objectClass=group)(objectClass=computer)"
    "(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)"
    "(objectClass=domain)(objectClass=container)"
    "(objectClass=msDS-GroupManagedServiceAccount)"
    "(objectClass=msDS-ManagedServiceAccount))"
)

_UAC_DISABLED = 0x0002
# UAC flags worth surfacing for delegation analysis.
_UAC_TRUSTED_FOR_DELEGATION = 0x80000        # unconstrained delegation
_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # constrained w/ protocol transition
_UAC_DONT_REQ_PREAUTH = 0x400000             # AS-REP roastable
_SAT_GMSA = 0x30000001
_SAT_SMSA = 0x30000000


def _first(rec, *keys, default=""):
    for k in keys:
        if k in rec and rec[k] not in (None, "", []):
            v = rec[k]
            return v[0] if isinstance(v, list) else v
    return default


def _as_list(v):
    if v is None or v == "":
        return []
    return list(v) if isinstance(v, list) else [v]


def _most_specific_class(classes) -> str:
    cl = {str(c).lower() for c in classes}
    # (Group) managed service accounts derive from computer but are principals we
    # want treated as user-like (local admin, SPNs, granted rights). Classify
    # them first so the computer base-class doesn't win.
    if "msds-groupmanagedserviceaccount" in cl or "msds-managedserviceaccount" in cl:
        return "user"
    if "pkicertificatetemplate" in cl:
        return "pKICertificateTemplate"
    if "pkienrollmentservice" in cl:
        return "pKIEnrollmentService"
    order = ["computer", "user", "group", "organizationalUnit",
             "groupPolicyContainer", "domain", "container"]
    mapping = {
        "computer": "computer", "user": "user", "group": "group",
        "organizationalunit": "organizationalUnit",
        "grouppolicycontainer": "groupPolicyContainer",
        "domaindns": "domain", "domain": "domain", "container": "container",
    }
    for want in order:
        if want.lower() in cl:
            return mapping[want.lower()]
    return "container"


def collect_schema_guids(client) -> dict:
    """Map objectType GUID -> friendly attribute/class/extended-right name.

    Reads the schema and configuration naming contexts. Best-effort: failures
    just mean GUIDs render as raw GUIDs.
    """
    names: dict[str, str] = {}
    # Schema attributes/classes carry schemaIDGUID.
    try:
        schema_base = f"CN=Schema,CN=Configuration,{_root_dn(client.base_dn)}"
        for rec in client.search("(|(objectClass=attributeSchema)(objectClass=classSchema))",
                                  ["lDAPDisplayName", "schemaIDGUID"],
                                  base=schema_base, want_sd=False):
            g = rec.get("schemaIDGUID")
            n = _first(rec, "lDAPDisplayName")
            if g and n:
                from impacket.uuid import bin_to_string
                gs = bin_to_string(g).lower() if isinstance(g, (bytes, bytearray)) else str(g).lower()
                names[gs] = str(n)
    except Exception as e:
        client.log(f"[collect] schema GUID map skipped: {e}", "info")
    # Extended rights carry rightsGuid (string form already).
    try:
        er_base = f"CN=Extended-Rights,CN=Configuration,{_root_dn(client.base_dn)}"
        for rec in client.search("(objectClass=controlAccessRight)",
                                  ["displayName", "cn", "rightsGuid"],
                                  base=er_base, want_sd=False):
            g = _first(rec, "rightsGuid")
            n = _first(rec, "displayName", "cn")
            if g and n:
                names[str(g).lower()] = str(n)
    except Exception as e:
        client.log(f"[collect] extended-rights map skipped: {e}", "info")
    client.log(f"[collect] schema/rights GUID names: {len(names)}", "info")
    return names


def collect_adcs(client, store, log=None) -> int:
    """Collect ADCS certificate templates + enrollment services (CAs) from the
    Configuration NC's PKI container, with their DACLs, and normalize each
    template's ESC-relevant attributes into ``obj.extra['adcs_template']``.

    Returns the number of ADCS objects added. Best-effort: if the PKI container
    isn't present (no ADCS) it logs and returns 0.
    """
    log = log or client.log
    from adcontrol import adcs as adcs_mod
    pki_base = (f"CN=Public Key Services,CN=Services,CN=Configuration,"
                f"{_root_dn(client.base_dn)}")
    flt = ("(|(objectClass=pKICertificateTemplate)"
           "(objectClass=pKIEnrollmentService)(objectClass=certificationAuthority))")
    attrs = _ATTRS  # includes the msPKI-* template attributes
    added = 0
    try:
        recs = list(client.search(flt, attrs, base=pki_base, want_sd=True))
    except Exception as e:
        log(f"[adcs] PKI container search skipped ({e})", "info")
        return 0
    for rec in recs:
        dn = rec.get("dn") or _first(rec, "distinguishedName")
        if not dn:
            continue
        classes = _as_list(rec.get("objectClass"))
        obj = RawObject(
            dn=dn, sid=_first(rec, "objectSid"), guid=_first(rec, "objectGUID"),
            sam=_first(rec, "sAMAccountName"),
            name=_first(rec, "displayName", "cn", "name"),
            object_class=_most_specific_class(classes),
            classes=[str(c) for c in classes],
        )
        blob = rec.get("nTSecurityDescriptor")
        if blob:
            owner, aces = sddl.parse_descriptor(blob, store.schema_guid_names)
            obj.owner_sid = owner
            obj.aces = aces
        if obj.object_class == "pKICertificateTemplate":
            obj.extra["adcs_template"] = adcs_mod.normalize_from_ldap(rec, _first)
        store.add(obj)
        added += 1
    log(f"[adcs] collected {added} certificate template/CA object(s)", "info")
    return added


def _root_dn(base_dn: str) -> str:
    """Strip any leading CN=/OU= components to get the DC=... root."""
    parts = [p for p in base_dn.split(",") if p.strip().upper().startswith("DC=")]
    return ",".join(parts)


def collect(client, log=None, smb_creds=None, dc_host=None, dc_ip=None,
            do_gpo=True, host_targets=None, session_targets=None) -> ObjectStore:
    """Collect the AD object graph (tier 1), then optionally the GPO plane
    (tier 2, on by default when *smb_creds* is supplied) and the per-host plane
    (tier 3, only when *host_targets* is a non-empty list).

    All planes write into the same ObjectStore; the GPO/host findings go to
    ``store.policy_rights`` and never mix with the ACL control graph.
    """
    log = log or client.log
    store = ObjectStore()
    store.base_dn = _root_dn(client.base_dn)
    store.domain = client.domain
    store.collected_at = datetime.datetime.now().isoformat(timespec="seconds")

    log("[collect] mapping schema / extended-right GUIDs...", "info")
    store.schema_guid_names = collect_schema_guids(client)

    log("[collect] pulling objects + security descriptors...", "info")
    count = 0
    for rec in client.search(_MAIN_FILTER, _ATTRS, base=store.base_dn, want_sd=True):
        dn = rec.get("dn") or _first(rec, "distinguishedName")
        if not dn:
            continue
        classes = _as_list(rec.get("objectClass"))
        obj = RawObject(
            dn=dn,
            sid=_first(rec, "objectSid"),
            guid=_first(rec, "objectGUID"),
            sam=_first(rec, "sAMAccountName"),
            name=_first(rec, "displayName", "cn", "name"),
            object_class=_most_specific_class(classes),
            classes=[str(c) for c in classes],
            members=_as_list(rec.get("member")),
            member_of=_as_list(rec.get("memberOf")),
            gplinks=_parse_gplink(_first(rec, "gPLink")),
        )
        try:
            obj.admin_count = int(_first(rec, "adminCount", default=0) or 0)
        except (ValueError, TypeError):
            obj.admin_count = 0
        try:
            obj.uac = int(_first(rec, "userAccountControl", default=0) or 0)
        except (ValueError, TypeError):
            obj.uac = 0
        obj.enabled = not (obj.uac & _UAC_DISABLED)

        spn = _as_list(rec.get("servicePrincipalName"))
        if spn:
            obj.extra["spn"] = spn
        if rec.get("msDS-AllowedToActOnBehalfOfOtherIdentity"):
            obj.extra["rbcd"] = True
        os_ = _first(rec, "operatingSystem")
        if os_:
            obj.extra["os"] = os_
        gpcpath = _first(rec, "gPCFileSysPath")
        if gpcpath:
            obj.extra["gpc_path"] = gpcpath
        dnsname = _first(rec, "dNSHostName")
        if dnsname:
            obj.extra["dns"] = dnsname

        blob = rec.get("nTSecurityDescriptor")
        if blob:
            owner, aces = sddl.parse_descriptor(blob, store.schema_guid_names)
            obj.owner_sid = owner
            obj.aces = aces

        # gMSA: mark it and turn its msDS-GroupMSAMembership SD into
        # ReadGMSAPassword control edges (who can retrieve its password).
        cl_low = {str(c).lower() for c in classes}
        if "msds-groupmanagedserviceaccount" in cl_low or "msds-managedserviceaccount" in cl_low:
            obj.extra["gmsa"] = True
        gmsa_sd = rec.get("msDS-GroupMSAMembership")
        if gmsa_sd:
            obj.aces.extend(sddl.parse_gmsa_membership(gmsa_sd))
            obj.extra["gmsa"] = True

        # Delegation flags (from UAC + msDS-AllowedToDelegateTo).
        if obj.uac & _UAC_TRUSTED_FOR_DELEGATION:
            obj.extra["unconstrained_delegation"] = True
        if obj.uac & _UAC_TRUSTED_TO_AUTH_FOR_DELEGATION:
            obj.extra["constrained_delegation_protocol_transition"] = True
        if obj.uac & _UAC_DONT_REQ_PREAUTH:
            obj.extra["asrep_roastable"] = True
        s2d = _as_list(rec.get("msDS-AllowedToDelegateTo"))
        if s2d:
            obj.extra["allowed_to_delegate_to"] = [str(x) for x in s2d]
        # SID history — a live SID-history injection surface.
        sidhist = _as_list(rec.get("sIDHistory"))
        if sidhist:
            obj.extra["sid_history"] = [sddl._sid_str(x) if isinstance(x, (bytes, bytearray))
                                        else str(x) for x in sidhist]
        # Description often holds credentials in the wild.
        desc = _first(rec, "description")
        if desc:
            obj.extra["description"] = str(desc)

        store.add(obj)
        count += 1
        if count % 500 == 0:
            log(f"[collect]   {count} objects...", "info")

    # Domain SID from the domain object (or infer from any principal SID).
    for obj in store.objects.values():
        if obj.object_class == "domain" and obj.sid:
            store.domain_sid = obj.sid
            break
    if not store.domain_sid:
        for obj in store.objects.values():
            if obj.sid.startswith("S-1-5-21-"):
                store.domain_sid = obj.sid.rsplit("-", 1)[0]
                break

    log(f"[collect] done: {count} objects, domain SID {store.domain_sid or '?'}", "info")

    # -- ADCS objects (tier 1, DC-only LDAP over the Configuration NC) ---------
    try:
        collect_adcs(client, store, log=log)
    except Exception as e:
        log(f"[adcs] collection failed: {e}", "warn")

    # -- tier 2: GPO plane (DC SYSVOL only) -----------------------------------
    if smb_creds is not None and do_gpo and dc_host:
        try:
            from adcontrol import gpo as gpo_mod
            gpo_mod.collect_gpo_rights(store, smb_creds, dc_host, dc_ip, log=log)
        except Exception as e:
            log(f"[gpo] plane failed: {e}", "warn")

    # -- tier 3: per-host plane (opt-in, fans out) ----------------------------
    if smb_creds is not None and host_targets:
        try:
            from adcontrol import hostrights as hr_mod
            hr_mod.collect_host_rights(store, smb_creds, host_targets, log=log)
        except Exception as e:
            log(f"[host] plane failed: {e}", "warn")

    # -- tier 3: live logon-session plane (opt-in, fans out) ------------------
    if smb_creds is not None and session_targets:
        try:
            from adcontrol import sessions as sess_mod
            sess_mod.collect_sessions(store, smb_creds, session_targets, log=log)
        except Exception as e:
            log(f"[sess] plane failed: {e}", "warn")

    return store


def _parse_gplink(gplink) -> list[str]:
    """gPLink is like '[LDAP://cn={GUID},...;0][LDAP://...;2]' -> list of GPO DNs."""
    if not gplink:
        return []
    out = []
    for chunk in str(gplink).split("]"):
        chunk = chunk.strip().lstrip("[")
        if not chunk.upper().startswith("LDAP://"):
            continue
        dn = chunk[len("LDAP://"):].split(";")[0]
        if dn:
            out.append(dn)
    return out
