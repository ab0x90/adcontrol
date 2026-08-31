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


# Class-name markers for (group) managed service accounts. NOTE: the gMSA
# samAccountType is SAM_MACHINE_ACCOUNT (805306369), identical to a plain
# computer, so it is NOT a usable discriminator; sMSAs use 805306368 which
# computers never use, so that one alone is safe.
_MSA_CLASS_MARKERS = ("msds-groupmanagedserviceaccount", "msds-managedserviceaccount")
_SMSA_SAT = "805306368"


def _is_gmsa(bh, classes) -> bool:
    """True if this BloodHound object is a (group) managed service account.

    Checks, in order of reliability: an explicit gmsa/msa property flag, the
    msDS-GroupMSAMembership property (who may retrieve the password), the class
    list, and the sMSA samAccountType. Deliberately does NOT use the gMSA
    samAccountType (805306369) — it is indistinguishable from a plain computer."""
    props = bh.get("Properties") or {}
    if props.get("gmsa") or props.get("msa"):
        return True
    if props.get("msds-groupmsamembership") or props.get("msdsgroupmsamembership"):
        return True
    cl = classes if isinstance(classes, str) else " ".join(str(c) for c in (classes or []))
    if any(m in cl.lower() for m in _MSA_CLASS_MARKERS):
        return True
    return str(props.get("samaccounttype") or "") == _SMSA_SAT


def _iter_bh_files(source: str):
    """Yield (raw_bytes, filename) for each JSON file in source, one at a time."""
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as z:
            for zi in z.namelist():
                if zi.lower().endswith(".json"):
                    yield z.read(zi), zi
    elif os.path.isdir(source):
        for f in sorted(glob.glob(os.path.join(source, "*.json"))):
            with open(f, "rb") as fh:
                yield fh.read(), os.path.basename(f)
    elif os.path.isfile(source) and source.lower().endswith(".json"):
        with open(source, "rb") as fh:
            yield fh.read(), os.path.basename(source)
    else:
        raise ValueError(f"not a BloodHound zip / json / directory: {source}")


def _cat_from_name(name: str) -> str:
    low = name.lower()
    for cat in ("users", "groups", "computers", "domains", "gpos", "ous",
                "certtemplates", "enterprisecas", "rootcas", "aiacas",
                "ntauthstores", "issuancepolicies", "containers"):
        if cat in low:
            return cat
    return "containers"


# BloodHound ADCS category -> our object_class. Certificate templates are the
# ESC-analysis targets; the CA/store categories are collected as generic ADCS
# objects (class kept distinct so they don't pollute the principal lists).
_ADCS_CAT_CLASS = {
    "certtemplates": "pKICertificateTemplate",
    "enterprisecas": "pKIEnrollmentService",
    "rootcas": "certificationAuthority",
    "aiacas": "certificationAuthority",
    "ntauthstores": "certificationAuthority",
    "issuancepolicies": "container",
}


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


def _materialize_orphan_host_trustees(store, log) -> int:
    """Create synthetic principal nodes for local-admin/RDP trustees that were
    never collected as their own object (missing SID) or landed as a
    non-principal container. Returns the count materialized.

    Only well-formed domain/forest SIDs are materialized — well-known SIDs
    (S-1-5-32-*, S-1-5-11, …) are left alone (they resolve by name and aren't
    selectable subjects anyway). The synthetic node is user-class so it flows
    through every principal-only view (local-admin table, pathfinding)."""
    made = 0
    for pr in store.policy_rights:
        if pr.plane != "host":
            continue
        for lbl, sid in zip(pr.trustees, getattr(pr, "trustee_sids", []) or []):
            if not sid or not sid.startswith("S-1-5-21-"):
                continue   # only real domain principals; skip built-ins/well-knowns
            existing = store.by_sid(sid)
            if existing is not None and existing.object_class in (
                    "user", "group", "computer"):
                continue   # already a usable principal
            if existing is not None:
                # Present but as a non-principal (e.g. container-classified gMSA):
                # promote it in place rather than duplicating.
                existing.object_class = "user"
                existing.classes = list(dict.fromkeys(existing.classes + ["user"]))
                existing.extra.setdefault("materialized_host_trustee", True)
                made += 1
                continue
            dn = f"CN={lbl},<materialized-host-trustee>"
            obj = RawObject(
                dn=dn, sid=sid, sam=(lbl if lbl and not lbl.startswith("S-1-") else ""),
                name=lbl, object_class="user", classes=["user"],
            )
            obj.extra["materialized_host_trustee"] = True
            store.add(obj)
            made += 1
    return made


def _host_rights_from_computer(bh_obj, store, log) -> int:
    """Turn a computer's BloodHound LocalGroups / UserRights into host-plane
    PolicyRight findings. Returns count added."""
    added = 0
    host = _prop(bh_obj, "name") or bh_obj.get("ObjectIdentifier", "")
    host_sid = _denamespace_sid(bh_obj.get("ObjectIdentifier", ""))

    def resolve_pairs(results):
        """[(label, sid)] for each member, SIDs denamespaced."""
        pairs = []
        for m in results or []:
            sid = _denamespace_sid(m.get("ObjectIdentifier", ""))
            o = store.by_sid(sid)
            label = o.label if o else (R.wellknown_name(sid) or sid)
            pairs.append((label, sid))
        return pairs

    for lg in bh_obj.get("LocalGroups") or []:
        # Determine which local group by the RID at the end of ObjectIdentifier.
        oid = lg.get("ObjectIdentifier", "")
        rid = oid.rsplit("-", 1)[-1] if oid else ""
        label_sev = _LOCAL_GROUP_LABELS.get(rid)
        if not label_sev:
            continue
        label, sev = label_sev
        pairs = resolve_pairs(lg.get("Results"))
        if pairs:
            store.policy_rights.append(PolicyRight(
                plane="host", right=label,
                trustees=[p[0] for p in pairs], trustee_sids=[p[1] for p in pairs],
                applies_to=host, applies_to_sid=host_sid, source=host, severity=sev,
                detail="BloodHound LocalGroups"))
            added += 1

    for ur in bh_obj.get("UserRights") or []:
        priv = ur.get("Privilege", "")
        if priv not in ("SeRemoteInteractiveLogonRight", "SeInteractiveLogonRight"):
            continue
        friendly = ("Allow log on through RDP" if priv == "SeRemoteInteractiveLogonRight"
                    else "Allow log on locally")
        pairs = resolve_pairs(ur.get("Results"))
        if pairs:
            store.policy_rights.append(PolicyRight(
                plane="host", right=f"{priv} ({friendly})",
                trustees=[p[0] for p in pairs], trustee_sids=[p[1] for p in pairs],
                applies_to=host, applies_to_sid=host_sid, source=host,
                severity="high" if "Remote" in priv else "medium",
                detail="BloodHound UserRights"))
            added += 1
    return added


def _slim_computer(bh: dict) -> dict:
    """Strip a BloodHound computer dict down to the 5 keys later passes need."""
    return {
        "ObjectIdentifier": bh.get("ObjectIdentifier", ""),
        "LocalGroups":        bh.get("LocalGroups") or [],
        "UserRights":         bh.get("UserRights") or [],
        "PrivilegedSessions": bh.get("PrivilegedSessions"),
        "RegistrySessions":   bh.get("RegistrySessions"),
        "Sessions":           bh.get("Sessions"),
    }


_CAT_OCLASS = {
    "users": "user", "groups": "group", "computers": "computer",
    "domains": "domain", "gpos": "groupPolicyContainer",
    "ous": "organizationalUnit", "containers": "container",
}


def import_zip(source: str, log=None) -> ObjectStore:
    """Build an ObjectStore from a BloodHound zip / directory / single json.

    Mirrors what collector.collect() produces from a live DC.
    Memory-efficient: streams one JSON file at a time, keeps only minimal
    inter-pass state (SID strings instead of full BH dicts).
    """
    import gc
    log = log or (lambda m, l="info": None)
    log(f"[bh] reading {source}", "info")

    store = ObjectStore()
    store.source = f"offline:bloodhound ({os.path.basename(source)})"
    store.collected_at = datetime.datetime.now().isoformat(timespec="seconds")

    # group DN -> list of raw member ObjectIdentifier strings (not full dicts)
    members_by_group: dict[str, list[str]] = {}
    # slimmed computer records — only the keys passes 3 & 4 actually read
    computers_slim: list[dict] = []
    total = 0
    cat_counts: dict[str, int] = {}

    # First pass: stream one JSON file at a time so raw parsed JSON is freed
    # as soon as each file is processed — never holding the entire collection.
    for raw, fname in _iter_bh_files(source):
        try:
            doc = json.loads(raw)
        except Exception:
            continue
        finally:
            del raw  # release compressed/raw bytes immediately

        cat = (doc.get("meta") or {}).get("type") or _cat_from_name(fname)
        objs = doc.get("data") or []
        cat_counts[cat] = cat_counts.get(cat, 0) + len(objs)
        total += len(objs)

        for bh in objs:
            oid = bh.get("ObjectIdentifier", "")
            sid = _denamespace_sid(oid)
            dn = _prop(bh, "distinguishedname") or oid
            classes = bh.get("_type") or cat
            oclass = _CAT_OCLASS.get(cat) or _ADCS_CAT_CLASS.get(cat, "container")
            is_gmsa = _is_gmsa(bh, classes)
            if is_gmsa:
                oclass = "user"

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
            if is_gmsa:
                obj.extra["gmsa"] = True
            if oclass == "pKICertificateTemplate":
                from adcontrol import adcs as adcs_mod
                obj.extra["adcs_template"] = adcs_mod.normalize_from_bh(
                    bh.get("Properties") or {})
            obj.enabled = bool(_prop(bh, "enabled", True))
            obj.admin_count = 1 if (_prop(bh, "admincount", False)
                                    or _prop(bh, "adminsdholderprotected", False)) else 0
            if _prop(bh, "serviceprincipalnames"):
                obj.extra["spn"] = _prop(bh, "serviceprincipalnames")
            if bh.get("DomainSID"):
                store.domain_sid = store.domain_sid or _denamespace_sid(bh["DomainSID"])

            for lk in bh.get("Links") or []:
                gid = lk.get("GUID") or lk.get("ObjectIdentifier")
                if gid:
                    obj.gplinks.append(gid)

            store.add(obj)

            if bh.get("Members"):
                # Store only SID strings — not the full BH member dicts.
                members_by_group[dn] = [
                    m.get("ObjectIdentifier", "") for m in bh["Members"]
                ]

            if cat == "computers":
                computers_slim.append(_slim_computer(bh))

            if cat == "domains" and not store.domain:
                store.domain = _prop(bh, "name") or ""
                store.base_dn = dn

        del objs  # let GC reclaim parsed objects for this file before next file

    if not total:
        raise ValueError("no objects found in BloodHound data")
    log(f"[bh] categories: " + ", ".join(f"{k}={v}" for k, v in cat_counts.items()), "info")
    gc.collect()

    # Second pass: invert Members -> member_of.  members_by_group now holds only
    # SID strings so the overhead is one str per member rather than a full dict.
    for gdn, member_oids in members_by_group.items():
        group = store.by_dn(gdn)
        if not group:
            continue
        for oid in member_oids:
            msid = _denamespace_sid(oid)
            mobj = store.by_sid(msid)
            if mobj:
                group.members.append(mobj.dn)
                mobj.member_of.append(gdn)

    del members_by_group
    gc.collect()

    # Third pass: host-plane findings from computer LocalGroups/UserRights.
    host_added = 0
    for bh in computers_slim:
        host_added += _host_rights_from_computer(bh, store, log)

    materialized = _materialize_orphan_host_trustees(store, log)
    if materialized:
        log(f"[bh] materialized {materialized} orphan host-plane principal(s)", "info")

    # Fourth pass: user↔host logon sessions.
    sess_added = _sessions_from_computers(computers_slim, store)

    del computers_slim
    gc.collect()

    store.build_session_indexes()
    if not store.domain and store.domain_sid:
        store.domain = ""
    log(f"[bh] imported {len(store)} objects, domain SID {store.domain_sid or '?'}, "
        f"{host_added} host-plane findings, {sess_added} sessions", "info")
    return store


# BloodHound computer session blocks, in descending collection confidence. The
# first two put the user's credentials on the host (reliable); plain Sessions is
# net-session enumeration (looser, can be stale).
_SESSION_BLOCKS = (
    ("PrivilegedSessions", "privileged"),
    ("RegistrySessions", "registry"),
    ("Sessions", "netsession"),
)


def _sessions_from_computers(computers_raw, store) -> int:
    """Parse each computer's session blocks into ``store.sessions``. A session
    row is ``{UserSID, ComputerSID}`` (SharpHound) — we denamespace the SIDs and
    tag each with the block's confidence ``kind``. Deduped on (user, host, kind)."""
    from adcontrol.model import Session
    seen = set()
    added = 0
    for bh in computers_raw:
        comp_sid = _denamespace_sid(bh.get("ObjectIdentifier", "") or "")
        for block, kind in _SESSION_BLOCKS:
            blk = bh.get(block) or {}
            for row in (blk.get("Results") or []):
                usid = _denamespace_sid(row.get("UserSID", "") or "")
                # ComputerSID in the row wins if present, else the computer's own.
                csid = _denamespace_sid(row.get("ComputerSID", "") or "") or comp_sid
                if not usid or not csid:
                    continue
                key = (usid, csid, kind)
                if key in seen:
                    continue
                seen.add(key)
                store.sessions.append(Session(user_sid=usid, computer_sid=csid, kind=kind))
                added += 1
    return added
