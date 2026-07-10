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
]

# One filter that captures every principal + container we care about controlling.
_MAIN_FILTER = (
    "(|(objectClass=user)(objectClass=group)(objectClass=computer)"
    "(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)"
    "(objectClass=domain)(objectClass=container))"
)

_UAC_DISABLED = 0x0002


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
    order = ["computer", "user", "group", "organizationalUnit",
             "groupPolicyContainer", "domain", "container"]
    cl = {str(c).lower() for c in classes}
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


def _root_dn(base_dn: str) -> str:
    """Strip any leading CN=/OU= components to get the DC=... root."""
    parts = [p for p in base_dn.split(",") if p.strip().upper().startswith("DC=")]
    return ",".join(parts)


def collect(client, log=None, smb_creds=None, dc_host=None, dc_ip=None,
            do_gpo=True, host_targets=None) -> ObjectStore:
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
