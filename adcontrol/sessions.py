"""
Live logon-session collection plane (tier 3, OPT-IN, fans out to member hosts).

BloodHound's session loop is what makes the ``HasSession`` attack-path avenue
work; a plain LDAP pull has none of it. This module fills that gap for *live*
collection: for each target host, over MS-RPC on port 445, it enumerates who is
logged on and writes :class:`~adcontrol.model.Session` records into the store —
the exact same shape the BloodHound importer produces — so pathfinding's
``subject → LocalAdmin → HOST → HasSession → victim`` chain works on a live pull.

Two RPC sources, in descending confidence (mirrors the importer's kinds):

  * **NetWkstaUserEnum** (``\\wkssvc``, level 1) — accounts *interactively*
    logged on (their credentials are on the box). Mapped to kind ``registry``
    — reliable, chained into attack paths.
  * **NetSessionEnum** (``\\srvsvc``, level 10) — accounts with an SMB session to
    the host. Looser (often just the username + source IP, can be stale), mapped
    to kind ``netsession`` — informational, NOT chained into paths.

Both return account NAMES, not SIDs; we resolve them to SIDs against the store
(by sAMAccountName / label) so they join the object graph. Sessions whose user
or host can't be resolved to a SID are dropped (they can't participate in the
SID-based graph). Per-host failures are logged and skipped — one dead host never
aborts the sweep. Opt-in only, exactly like ``hostrights`` (tier 3).
"""

from __future__ import annotations

from adcontrol.model import Session


# Accounts that are never interesting as a "session" (machine/service noise).
_SKIP_USERS = {"", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}


def _host_sid(store, host: str) -> str:
    """SID of the computer object matching *host* (by dNSHostName / sAMAccountName),
    or '' if it isn't a collected computer."""
    hl = (host or "").lower()
    short = hl.split(".", 1)[0]
    for obj in store.objects.values():
        if obj.object_class != "computer":
            continue
        dns = (obj.extra.get("dns") or "").lower()
        sam = (obj.sam.rstrip("$").lower() if obj.sam else "")
        if hl and (dns == hl or sam == short):
            return obj.sid or ""
    return ""


def _user_sid(store, username: str, domain: str = "") -> str:
    """Resolve a logged-on account NAME to a collected user/computer SID.

    Tries sAMAccountName and label (case-insensitive). A trailing '$' (machine
    account) is honored. Returns '' when the account isn't in the store."""
    if not username:
        return ""
    uname = username.strip().lower()
    if uname.upper() in _SKIP_USERS:
        return ""
    # Build a lazy name index on the store (cached on the store object).
    idx = getattr(store, "_name_sid_index", None)
    if idx is None:
        idx = {}
        for obj in store.objects.values():
            if obj.object_class not in ("user", "computer"):
                continue
            if obj.sam:
                idx.setdefault(obj.sam.lower(), obj.sid)
            if obj.name:
                idx.setdefault(obj.name.lower(), obj.sid)
        store._name_sid_index = idx
    return idx.get(uname) or idx.get(uname + "$") or ""


def _netwksta_users(smb, host, log):
    """[(username, domain)] for accounts interactively logged on (level 1)."""
    from impacket.dcerpc.v5 import transport, wkst
    out = []
    try:
        rpc = transport.SMBTransport(host, filename=r"\wkssvc", smb_connection=smb)
        dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(wkst.MSRPC_UUID_WKST)
        resp = wkst.hNetrWkstaUserEnum(dce, 1)
        for u in resp["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]:
            name = u["wkui1_username"][:-1] if u["wkui1_username"] else ""
            dom = u["wkui1_logon_domain"][:-1] if u["wkui1_logon_domain"] else ""
            if name:
                out.append((name, dom))
        dce.disconnect()
    except Exception as e:
        log(f"[sess] {host}: NetWkstaUserEnum failed: {e}", "info")
    return out


def _netsession_users(smb, host, log):
    """[username] for accounts with an SMB session to the host (level 10)."""
    from impacket.dcerpc.v5 import transport, srvs
    from impacket.dcerpc.v5.dtypes import NULL
    out = []
    try:
        rpc = transport.SMBTransport(host, filename=r"\srvsvc", smb_connection=smb)
        dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)
        for s in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
            name = s["sesi10_username"][:-1] if s["sesi10_username"] else ""
            if name:
                out.append(name)
        dce.disconnect()
    except Exception as e:
        log(f"[sess] {host}: NetSessionEnum failed: {e}", "info")
    return out


def collect_sessions(store, smb_creds, hosts, log=None) -> int:
    """Query each host in *hosts* and append :class:`Session` records to the
    store. *hosts* is an iterable of (host, ip_or_None). Returns count added.

    NetWkstaUserEnum → kind 'registry' (reliable, chained); NetSessionEnum →
    kind 'netsession' (informational). Deduped on (user_sid, host_sid, kind)."""
    log = log or smb_creds.log
    hosts = list(hosts)
    if not hosts:
        log("[sess] no target hosts — session plane skipped", "info")
        return 0
    log(f"[sess] enumerating logon sessions on {len(hosts)} host(s) via "
        "NetWkstaUserEnum + NetSessionEnum (opt-in plane)", "info")
    seen: set[tuple] = set()
    added = 0
    for host, ip in hosts:
        host_sid = _host_sid(store, host)
        if not host_sid:
            log(f"[sess] {host}: not a collected computer — skipped", "info")
            continue
        smb = smb_creds.connect(host, ip)
        if not smb:
            continue
        # Interactive logons (reliable).
        for uname, dom in _netwksta_users(smb, host, log):
            usid = _user_sid(store, uname, dom)
            if not usid:
                continue
            key = (usid, host_sid, "registry")
            if key in seen:
                continue
            seen.add(key)
            store.sessions.append(Session(user_sid=usid, computer_sid=host_sid,
                                          kind="registry"))
            added += 1
        # SMB sessions (looser).
        for uname in _netsession_users(smb, host, log):
            usid = _user_sid(store, uname)
            if not usid:
                continue
            key = (usid, host_sid, "netsession")
            if key in seen or (usid, host_sid, "registry") in seen:
                continue   # already have a higher-confidence record for this pair
            seen.add(key)
            store.sessions.append(Session(user_sid=usid, computer_sid=host_sid,
                                          kind="netsession"))
            added += 1
        try:
            smb.close()
        except Exception:
            pass
    store.build_session_indexes()
    log(f"[sess] collected {added} logon session(s)", "info")
    return added
