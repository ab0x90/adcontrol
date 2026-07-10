"""
Offline import of a BloodHound / SharpHound collection into an ObjectStore.

This is the offline path the model layer was designed for: instead of querying a
DC live, we read a BloodHound zip (or a directory of its JSON files) and populate
the same ObjectStore that the live collector produces, so graph / analyze /
report / GUI all work unchanged.

Supported input: SharpHound multi-file JSON (users/groups/computers/domains/
gpos/ous/containers), BloodHound CE format (meta.version 5/6). BloodHound has
already resolved the DACLs into an ``Aces`` array of {PrincipalSID, RightName,
IsInherited}, so no nTSecurityDescriptor parsing is needed — we translate the
RightName vocabulary into this tool's right names.

BloodHound quirks handled:
  * Membership is stored one-way as ``Members`` on groups (no memberOf); we
    invert it so the graph's memberOf walk works.
  * Built-in SIDs are namespaced per-domain ("DOMAIN-S-1-5-32-544"); we keep the
    namespaced form as the object key but also index the bare well-known SID so
    ACE trustees resolve.
  * Computers carry BloodHound's own ``LocalGroups`` / ``UserRights`` — we turn
    these into host-plane PolicyRight findings (RDP / local admin) with no host
    contact.
"""

from __future__ import annotations

import io
import os
import json
import glob
import zipfile
import datetime

from adcontrol.model import ObjectStore, RawObject, Ace, PolicyRight
from adcontrol import rights as R

# BloodHound RightName  ->  (this tool's right name, severity)
_RIGHT_MAP = {
    "GenericAll":            ("GenericAll", "high"),
    "GenericWrite":          ("GenericWrite", "high"),
    "WriteDacl":             ("WriteDacl", "high"),
    "WriteOwner":            ("WriteOwner", "high"),
    "Owns":                  ("Owns (implicit WriteDacl)", "high"),
    "AllExtendedRights":     ("AllExtendedRights", "high"),
    "GetChanges":            ("DS-Replication-Get-Changes", "high"),
    "GetChangesAll":         ("DS-Replication-Get-Changes-All", "high"),
    "GetChangesInFilteredSet": ("DS-Replication-Get-Changes-In-Filtered-Set", "medium"),
    "ForceChangePassword":   ("User-Force-Change-Password", "high"),
    "AddMember":             ("AddMember", "high"),
    "AddSelf":               ("Self-Membership", "high"),
    "AddKeyCredentialLink":  ("WriteProperty:msDS-KeyCredentialLink", "high"),
    "WriteSPN":              ("WriteProperty:Service-Principal-Name", "high"),
    "AddAllowedToAct":       ("WriteProperty:msDS-AllowedToActOnBehalfOfOtherIdentity", "high"),
    "AllowedToAct":          ("WriteProperty:msDS-AllowedToActOnBehalfOfOtherIdentity", "high"),
    "WriteAccountRestrictions": ("WriteProperty:User-Account-Restrictions", "medium"),
    "ReadLAPSPassword":      ("ReadLAPSPassword", "high"),
    "ReadGMSAPassword":      ("ReadGMSAPassword", "high"),
    "WriteGPLink":           ("WriteProperty:gPLink", "high"),
    "DCSync":                ("DCSync (replicate secrets)", "high"),
    "SyncLAPSPassword":      ("ReadLAPSPassword", "high"),
    "ManageCertificates":    ("ExtendedRight:Manage-Certificates", "medium"),
    "Enroll":                ("Certificate-Enrollment", "medium"),
}

# BloodHound ObjectType -> our object_class
_TYPE_MAP = {
    "User": "user", "Group": "group", "Computer": "computer",
    "Domain": "domain", "GPO": "groupPolicyContainer", "OU": "organizationalUnit",
    "Container": "container", "Base": "container",
}

# BloodHound local-group RID/name -> host PolicyRight label (for computers'
# LocalGroups data).
_LOCAL_GROUP_LABELS = {
    "544": ("Local Administrators (local admin)", "high"),
    "555": ("Local Remote Desktop Users (can RDP)", "high"),
    "562": ("Local Distributed COM Users", "medium"),
    "580": ("Local Remote Management Users", "medium"),
}


def _denamespace_sid(sid: str) -> str:
    """'ITDEV.CORP-S-1-5-32-544' -> 'S-1-5-32-544'; leaves normal SIDs alone."""
    if not sid:
        return sid
    i = sid.find("S-1-")
    return sid[i:] if i > 0 else sid


def _prop(obj, key, default=""):
    return (obj.get("Properties") or {}).get(key, default)


def _load_json_files(source: str) -> dict[str, list]:
    """Return {category: [objects]} from a zip path or a directory of json files.

    Category is inferred from meta.type (users/groups/…)."""
    buckets: dict[str, list] = {}

    def ingest(raw: bytes, name: str):
        try:
            doc = json.loads(raw)
        except Exception:
            return
        cat = (doc.get("meta") or {}).get("type") or _cat_from_name(name)
        buckets.setdefault(cat, []).extend(doc.get("data", []))

    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as z:
            for zi in z.namelist():
                if zi.lower().endswith(".json"):
                    ingest(z.read(zi), zi)
    elif os.path.isdir(source):
        for f in glob.glob(os.path.join(source, "*.json")):
            with open(f, "rb") as fh:
                ingest(fh.read(), os.path.basename(f))
    elif os.path.isfile(source) and source.lower().endswith(".json"):
        with open(source, "rb") as fh:
            ingest(fh.read(), os.path.basename(source))
    else:
        raise ValueError(f"not a BloodHound zip / json / directory: {source}")
    return buckets


def _cat_from_name(name: str) -> str:
    low = name.lower()
    for cat in ("users", "groups", "computers", "domains", "gpos", "ous", "containers"):
        if cat in low:
            return cat
    return "containers"


def _translate_aces(bh_obj, log) -> tuple[str, list[Ace]]:
    """Return (owner_sid, [Ace]) from a BloodHound object's Aces array."""
    owner = ""
    aces: list[Ace] = []
    for a in bh_obj.get("Aces") or []:
        rn = a.get("RightName", "")
        trustee = _denamespace_sid(a.get("PrincipalSID", ""))
        if rn == "Owns":
            owner = owner or trustee
        mapped = _RIGHT_MAP.get(rn)
        if not mapped:
            # Unknown BloodHound right — keep it visible rather than dropping it.
            mapped = (f"ExtendedRight:{rn}", "medium")
        name, sev = mapped
        aces.append(Ace(
            trustee_sid=trustee, right=name, severity=sev,
            applies_to="", inherited=bool(a.get("IsInherited")),
        ))
    return owner, aces


def _host_rights_from_computer(bh_obj, store, log) -> int:
    """Turn a computer's BloodHound LocalGroups / UserRights into host-plane
    PolicyRight findings. Returns count added."""
    added = 0
    host = _prop(bh_obj, "name") or bh_obj.get("ObjectIdentifier", "")

    def resolve(sid):
        sid = _denamespace_sid(sid)
        o = store.by_sid(sid)
        return o.label if o else (R.wellknown_name(sid) or sid)

    for lg in bh_obj.get("LocalGroups") or []:
        # Determine which local group by the RID at the end of ObjectIdentifier.
        oid = lg.get("ObjectIdentifier", "")
        rid = oid.rsplit("-", 1)[-1] if oid else ""
        label_sev = _LOCAL_GROUP_LABELS.get(rid)
        if not label_sev:
            continue
        label, sev = label_sev
        members = [resolve(m.get("ObjectIdentifier", "")) for m in (lg.get("Results") or [])]
        if members:
            store.policy_rights.append(PolicyRight(
                plane="host", right=label, trustees=members,
                applies_to=host, source=host, severity=sev,
                detail="BloodHound LocalGroups"))
            added += 1

    for ur in bh_obj.get("UserRights") or []:
        priv = ur.get("Privilege", "")
        if priv not in ("SeRemoteInteractiveLogonRight", "SeInteractiveLogonRight"):
            continue
        friendly = ("Allow log on through RDP" if priv == "SeRemoteInteractiveLogonRight"
                    else "Allow log on locally")
        members = [resolve(m.get("ObjectIdentifier", "")) for m in (ur.get("Results") or [])]
        if members:
            store.policy_rights.append(PolicyRight(
                plane="host", right=f"{priv} ({friendly})", trustees=members,
                applies_to=host, source=host,
                severity="high" if "Remote" in priv else "medium",
                detail="BloodHound UserRights"))
            added += 1
    return added


def import_zip(source: str, log=None) -> ObjectStore:
    """Build an ObjectStore from a BloodHound zip / directory / single json.

    Mirrors what collector.collect() produces from a live DC.
    """
    log = log or (lambda m, l="info": None)
    log(f"[bh] reading {source}", "info")
    buckets = _load_json_files(source)
    total = sum(len(v) for v in buckets.values())
    log(f"[bh] categories: " + ", ".join(f"{k}={len(v)}" for k, v in buckets.items()), "info")
    if not total:
        raise ValueError("no objects found in BloodHound data")

    store = ObjectStore()
    store.source = f"offline:bloodhound ({os.path.basename(source)})"
    store.collected_at = datetime.datetime.now().isoformat(timespec="seconds")

    # First pass: create every object (so membership inversion can resolve DNs).
    members_by_group: dict[str, list[str]] = {}   # group DN -> [member DN]
    computers_raw = []

    for cat, objs in buckets.items():
        for bh in objs:
            oid = bh.get("ObjectIdentifier", "")
            sid = _denamespace_sid(oid)
            dn = _prop(bh, "distinguishedname") or oid
            classes = bh.get("_type") or cat
            # object_class from meta category (more reliable than per-object type)
            oclass = {
                "users": "user", "groups": "group", "computers": "computer",
                "domains": "domain", "gpos": "groupPolicyContainer",
                "ous": "organizationalUnit", "containers": "container",
            }.get(cat, "container")

            owner, aces = _translate_aces(bh, log)
            obj = RawObject(
                dn=dn, sid=sid,
                guid=(oid if oid.count("-") == 4 and "S-1-" not in oid else ""),
                sam=_prop(bh, "samaccountname"),
                name=_prop(bh, "name"),
                object_class=oclass,
                classes=[oclass],
                owner_sid=owner, aces=aces,
            )
            obj.enabled = bool(_prop(bh, "enabled", True))
            obj.admin_count = 1 if _prop(bh, "adminsdholderprotected", False) else 0
            spn = bh.get("SPNTargets") or []
            if _prop(bh, "serviceprincipalnames"):
                obj.extra["spn"] = _prop(bh, "serviceprincipalnames")
            if bh.get("DomainSID"):
                store.domain_sid = store.domain_sid or _denamespace_sid(bh["DomainSID"])

            # GPO links on OUs/domain (BloodHound stores under "Links").
            for lk in bh.get("Links") or []:
                gid = lk.get("GUID") or lk.get("ObjectIdentifier")
                if gid:
                    obj.gplinks.append(gid)

            store.add(obj)

            # Stash raw Members for a second-pass inversion once all objects exist.
            if bh.get("Members"):
                members_by_group[dn] = bh["Members"]

            if cat == "computers":
                computers_raw.append(bh)

            if cat == "domains" and not store.domain:
                store.domain = _prop(bh, "name") or ""
                store.base_dn = dn

    # Second pass: invert Members -> member_of, resolving member SIDs to DNs.
    for gdn, members in members_by_group.items():
        group = store.by_dn(gdn)
        if not group:
            continue
        for m in members:
            msid = _denamespace_sid(m.get("ObjectIdentifier", ""))
            mobj = store.by_sid(msid)
            if mobj:
                group.members.append(mobj.dn)
                mobj.member_of.append(gdn)

    # Third pass: host-plane findings from computer LocalGroups/UserRights.
    host_added = 0
    for bh in computers_raw:
        host_added += _host_rights_from_computer(bh, store, log)

    if not store.domain and store.domain_sid:
        store.domain = ""
    log(f"[bh] imported {len(store)} objects, domain SID {store.domain_sid or '?'}, "
        f"{host_added} host-plane findings", "info")
    return store
