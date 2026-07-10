r"""
GPO-delivered rights plane (tier 2) — reads GPOs from the DC's SYSVOL share ONLY.

No member host is touched. For every ``groupPolicyContainer`` already in the
store we read, over ``\\<dc>\SYSVOL``:

  * ``Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf``
      - ``[Privilege Rights]``  -> user-rights assignment, notably
        ``SeRemoteInteractiveLogonRight`` (Allow log on through RDP),
        ``SeInteractiveLogonRight``, ``SeNetworkLogonRight``, and the
        admin-equivalent logon rights.
      - ``[Group Membership]``  -> Restricted Groups (e.g. adds a domain group to
        local Administrators / Remote Desktop Users on linked machines).
  * ``Machine\Preferences\Groups\Groups.xml``
      - GPP local group membership (add members to a local group).

Each finding becomes a :class:`~adcontrol.model.PolicyRight` (plane="gpo") whose
``applies_to`` lists the OUs/domain the GPO is linked to (from gPLink already in
the store), so a report can say *which machines* inherit the right.
"""

from __future__ import annotations

import io
import configparser
import xml.etree.ElementTree as ET

from adcontrol.model import PolicyRight

# User-right constant -> (friendly, severity). Focus on logon/admin-relevant ones.
_USER_RIGHTS = {
    "SeRemoteInteractiveLogonRight": ("Allow log on through Remote Desktop (RDP)", "high"),
    "SeDenyRemoteInteractiveLogonRight": ("Deny log on through RDP", "low"),
    "SeInteractiveLogonRight": ("Allow log on locally", "medium"),
    "SeNetworkLogonRight": ("Access this computer from the network", "low"),
    "SeBackupPrivilege": ("Back up files and directories (SeBackup)", "high"),
    "SeRestorePrivilege": ("Restore files and directories (SeRestore)", "high"),
    "SeDebugPrivilege": ("Debug programs (SeDebug)", "high"),
    "SeTakeOwnershipPrivilege": ("Take ownership (SeTakeOwnership)", "high"),
    "SeImpersonatePrivilege": ("Impersonate a client (SeImpersonate)", "high"),
    "SeLoadDriverPrivilege": ("Load and unload device drivers", "high"),
    "SeTcbPrivilege": ("Act as part of the operating system (SeTcb)", "high"),
    "SeAssignPrimaryTokenPrivilege": ("Replace a process-level token", "medium"),
    "SeServiceLogonRight": ("Log on as a service", "low"),
    "SeBatchLogonRight": ("Log on as a batch job", "low"),
}

# Restricted-Groups local groups worth surfacing (name substrings, case-insens).
_LOCAL_GROUPS_OF_INTEREST = {
    "administrators": "high",
    "remote desktop users": "high",
    "remote management users": "medium",
    "backup operators": "high",
    "power users": "medium",
    "distributed com users": "medium",
}

_GPT_INF = "Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
_GPP_GROUPS = "Preferences\\Groups\\Groups.xml"


def _read_sysvol_file(smb, share, path, log):
    """Read a file from a SYSVOL-style share into bytes, or None if absent."""
    buf = io.BytesIO()
    try:
        smb.getFile(share, path, buf.write)
        return buf.getvalue()
    except Exception:
        return None


def _sysvol_rel(gpc_path):
    r"""Turn a gPCFileSysPath (\\domain\SysVol\domain\Policies\{GUID}) into the
    share ('SysVol') and the path under it."""
    p = gpc_path.replace("/", "\\").lstrip("\\")
    parts = p.split("\\")
    # parts: [domain, 'SysVol', domain, 'Policies', '{GUID}', ...]
    if len(parts) < 5:
        return None, None
    share = parts[1]                     # 'SysVol'
    rel = "\\".join(parts[2:])           # domain\Policies\{GUID}\...
    return share, rel


def _clean_trustee(raw):
    """GptTmpl user-rights values look like '*S-1-5-32-544,*S-1-5-21-...' or
    plain names; strip the leading '*' from SIDs."""
    out = []
    for t in raw.split(","):
        t = t.strip()
        if not t:
            continue
        out.append(t[1:] if t.startswith("*") else t)
    return out


def _parse_gpttmpl(data, gpo_name, applies_to, resolve_sid):
    rights = []
    try:
        text = data.decode("utf-16", errors="ignore")
        if "[" not in text:
            text = data.decode("utf-8", errors="ignore")
    except Exception:
        return rights
    cp = configparser.RawConfigParser(delimiters=("=",), strict=False)
    cp.optionxform = str
    try:
        cp.read_string(text)
    except Exception:
        return rights

    if cp.has_section("Privilege Rights"):
        for key, val in cp.items("Privilege Rights"):
            info = _USER_RIGHTS.get(key.strip())
            if not info:
                continue
            trustees = [resolve_sid(t) for t in _clean_trustee(val)]
            if not trustees:
                continue
            friendly, sev = info
            rights.append(PolicyRight(
                plane="gpo", right=f"{key.strip()} ({friendly})",
                trustees=trustees, applies_to=applies_to, source=gpo_name,
                severity=sev, detail="user-rights assignment"))

    if cp.has_section("Group Membership"):
        # Keys like 'Administrators__Members' = <members>, or
        # '*S-1-5-32-544__Members' = ...
        for key, val in cp.items("Group Membership"):
            if not key.endswith("__Members"):
                continue
            grp = key[:-len("__Members")]
            grp_name = resolve_sid(grp[1:] if grp.startswith("*") else grp).lower()
            sev = None
            for needle, s in _LOCAL_GROUPS_OF_INTEREST.items():
                if needle in grp_name:
                    sev = s
                    break
            if not sev or not val.strip():
                continue
            members = [resolve_sid(t) for t in _clean_trustee(val)]
            rights.append(PolicyRight(
                plane="gpo", right=f"Restricted Groups -> local '{grp_name}' membership",
                trustees=members, applies_to=applies_to, source=gpo_name,
                severity=sev, detail="Restricted Groups"))
    return rights


def _parse_gpp_groups(data, gpo_name, applies_to, resolve_sid):
    rights = []
    try:
        root = ET.fromstring(data)
    except Exception:
        return rights
    for grp in root.iter("Group"):
        props = grp.find("Properties")
        if props is None:
            continue
        gname = (props.get("groupName") or grp.get("name") or "").lower()
        sev = None
        for needle, s in _LOCAL_GROUPS_OF_INTEREST.items():
            if needle in gname:
                sev = s
                break
        if not sev:
            continue
        members = []
        mem_el = props.find("Members")
        if mem_el is not None:
            for m in mem_el.findall("Member"):
                if (m.get("action") or "ADD").upper() != "ADD":
                    continue
                sid = m.get("sid")
                name = m.get("name") or ""
                members.append(resolve_sid(sid) if sid else name)
        if members:
            rights.append(PolicyRight(
                plane="gpo", right=f"GPP -> local '{gname}' membership",
                trustees=members, applies_to=applies_to, source=gpo_name,
                severity=sev, detail="Group Policy Preferences"))
    return rights


def _gpo_applies_to(store, gpo_dn):
    """Which OUs / domain link this GPO (from gPLink already collected)."""
    linked = []
    low = gpo_dn.lower()
    for obj in store.objects.values():
        if any(low == g.lower() for g in obj.gplinks):
            linked.append(obj.dn)
    return linked


def collect_gpo_rights(store, smb_creds, dc_host, dc_ip=None, log=None):
    """Populate ``store.policy_rights`` with GPO-delivered rights. Returns count."""
    log = log or smb_creds.log
    gpos = [o for o in store.objects.values() if o.object_class == "groupPolicyContainer"]
    if not gpos:
        log("[gpo] no groupPolicyContainer objects in store — skipping", "info")
        return 0

    smb = smb_creds.connect(dc_host, dc_ip)
    if not smb:
        log(f"[gpo] could not connect to \\\\{dc_host}\\SYSVOL — skipping GPO plane", "warn")
        return 0

    def resolve_sid(s):
        if s and s.startswith("S-1-"):
            obj = store.by_sid(s)
            if obj:
                return obj.label
            from adcontrol import rights as R
            return R.wellknown_name(s) or s
        return s

    log(f"[gpo] reading {len(gpos)} GPO(s) from \\\\{dc_host}\\SYSVOL", "info")
    added = 0
    for gpo in gpos:
        gpc = gpo.extra.get("gpc_path", "")
        if not gpc:
            continue
        share, rel = _sysvol_rel(gpc)
        if not share:
            continue
        gpo_name = gpo.name or gpo.dn
        applies = _gpo_applies_to(store, gpo.dn)
        applies_str = ", ".join(applies) if applies else "(GPO not linked / unlinked)"

        inf = _read_sysvol_file(smb, share, rel.rstrip("\\") + "\\" + _GPT_INF, log)
        if inf:
            for pr in _parse_gpttmpl(inf, gpo_name, applies_str, resolve_sid):
                store.policy_rights.append(pr); added += 1
        gpp = _read_sysvol_file(smb, share, rel.rstrip("\\") + "\\" + _GPP_GROUPS, log)
        if gpp:
            for pr in _parse_gpp_groups(gpp, gpo_name, applies_str, resolve_sid):
                store.policy_rights.append(pr); added += 1

    try:
        smb.close()
    except Exception:
        pass
    log(f"[gpo] collected {added} GPO-delivered right(s)", "info")
    return added
