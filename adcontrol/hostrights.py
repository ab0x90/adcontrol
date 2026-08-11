"""
Per-host RDP / logon rights plane (tier 3) — OPT-IN, fans out to member hosts.

Only runs when the caller explicitly enables it (``--host-rights`` for all
collected computers, or ``--hosts`` for a specific list). For each target host,
over MS-RPC on port 445:

  * **SAMR** — enumerate members of the local ``Administrators`` (RID 544) and
    ``Remote Desktop Users`` (RID 555) aliases in the *builtin* domain. This is
    the direct 'who is local admin / who can RDP here' answer.
  * **LSA**  — ``LsarEnumerateAccountsWithUserRight`` for
    ``SeRemoteInteractiveLogonRight`` (Allow log on through RDP) and
    ``SeInteractiveLogonRight`` — the user-rights assignment, resolved to names.

Each finding becomes a :class:`~adcontrol.model.PolicyRight` (plane="host"),
kept in ``store.policy_rights`` separate from the AD-object control graph.

Failures per host are logged and skipped — one unreachable host never aborts the
sweep.
"""

from __future__ import annotations

from adcontrol.model import PolicyRight
from adcontrol.smbauth import is_access_denied

# Builtin local-alias RIDs.
_ALIAS_ADMINS = 544
_ALIAS_RDP = 555
_ALIAS_LABELS = {_ALIAS_ADMINS: "Administrators (local admin)",
                 _ALIAS_RDP: "Remote Desktop Users (can RDP)"}
_ALIAS_SEV = {_ALIAS_ADMINS: "high", _ALIAS_RDP: "high"}

_USER_RIGHTS = [
    ("SeRemoteInteractiveLogonRight", "Allow log on through RDP", "high"),
    ("SeInteractiveLogonRight", "Allow log on locally", "medium"),
]


def _samr_local_members(smb, host, log):
    """Return {rid: [member_sid, ...]} for the builtin Administrators/RDP aliases."""
    from impacket.dcerpc.v5 import transport, samr
    out = {}
    try:
        rpc = transport.SMBTransport(host, filename=r"\samr", smb_connection=smb)
        dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(samr.MSRPC_UUID_SAMR)
        server = samr.hSamrConnect(dce)["ServerHandle"]
        # The builtin domain is looked up by name "Builtin".
        dom_sid = samr.hSamrLookupDomainInSamServer(dce, server, "Builtin")["DomainId"]
        dom = samr.hSamrOpenDomain(dce, server, domainId=dom_sid)["DomainHandle"]
        for rid in (_ALIAS_ADMINS, _ALIAS_RDP):
            try:
                alias = samr.hSamrOpenAlias(dce, dom, aliasId=rid)["AliasHandle"]
                members = samr.hSamrGetMembersInAlias(dce, alias)
                sids = []
                for m in members["Members"]["Sids"]:
                    sids.append(m["SidPointer"].formatCanonical())
                out[rid] = sids
            except Exception as e:
                if is_access_denied(e):
                    log(f"[host] {host}: alias {rid} read access denied — scan "
                        "account is likely not a local admin on this host", "info")
                else:
                    log(f"[host] {host}: alias {rid} read failed: {e}", "info")
        dce.disconnect()
    except Exception as e:
        if is_access_denied(e):
            log(f"[host] {host}: SAMR access denied — scan account is likely "
                "not a local admin on this host", "warn")
        else:
            log(f"[host] {host}: SAMR failed: {e}", "warn")
    return out


def _lsa_user_rights(smb, host, log):
    """Return {right_const: [sid, ...]} for the logon user-rights we care about."""
    from impacket.dcerpc.v5 import transport, lsad
    from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
    out = {}
    try:
        rpc = transport.SMBTransport(host, filename=r"\lsarpc", smb_connection=smb)
        dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(lsad.MSRPC_UUID_LSAD)
        pol = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED)["PolicyHandle"]
        for const, _friendly, _sev in _USER_RIGHTS:
            try:
                resp = lsad.hLsarEnumerateAccountsWithUserRight(dce, pol, const)
                sids = [s["Sid"].formatCanonical() for s in resp["EnumerationBuffer"]["Information"]]
                if sids:
                    out[const] = sids
            except Exception:
                # right not assigned to anyone / not present -> skip quietly
                pass
        dce.disconnect()
    except Exception as e:
        if is_access_denied(e):
            log(f"[host] {host}: LSA access denied — scan account is likely "
                "not a local admin on this host", "warn")
        else:
            log(f"[host] {host}: LSA failed: {e}", "warn")
    return out


def _resolve(store, sid):
    obj = store.by_sid(sid)
    if obj:
        return obj.label
    from adcontrol import rights as R
    return R.wellknown_name(sid) or sid


def _host_sid(store, host):
    """SID of the computer object matching *host* (by dns/sam), or '' if unknown."""
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


def collect_host_rights(store, smb_creds, hosts, log=None):
    """Query each host in *hosts* and append PolicyRight(plane='host') findings.

    *hosts* is an iterable of (host, ip_or_None). Returns count of findings.
    """
    log = log or smb_creds.log
    hosts = list(hosts)
    if not hosts:
        log("[host] no target hosts — host-rights plane skipped", "info")
        return 0
    log(f"[host] querying {len(hosts)} host(s) via SAMR + LSA (opt-in plane)", "info")
    added = 0
    for host, ip in hosts:
        log(f"[host] -> {host}", "info")
        smb = smb_creds.connect(host, ip)
        if not smb:
            continue
        host_sid = _host_sid(store, host)
        # SAMR local group membership.
        for rid, sids in _samr_local_members(smb, host, log).items():
            if not sids:
                continue
            store.policy_rights.append(PolicyRight(
                plane="host", right=f"Local {_ALIAS_LABELS[rid]}",
                trustees=[_resolve(store, s) for s in sids], trustee_sids=list(sids),
                applies_to=host, applies_to_sid=host_sid, source=host,
                severity=_ALIAS_SEV[rid], detail="SAMR local alias membership"))
            added += 1
        # LSA user rights.
        lsa = _lsa_user_rights(smb, host, log)
        for const, friendly, sev in _USER_RIGHTS:
            sids = lsa.get(const)
            if not sids:
                continue
            store.policy_rights.append(PolicyRight(
                plane="host", right=f"{const} ({friendly})",
                trustees=[_resolve(store, s) for s in sids], trustee_sids=list(sids),
                applies_to=host, applies_to_sid=host_sid, source=host, severity=sev,
                detail="LSA user-rights assignment"))
            added += 1
        try:
            smb.close()
        except Exception:
            pass
        log(f"[host] done {host}", "info")
    log(f"[host] collected {added} per-host right finding(s)", "info")
    return added


def hosts_from_store(store):
    """All enabled computer objects -> (host, None) for --host-rights."""
    out = []
    for obj in store.objects.values():
        if obj.object_class == "computer" and obj.enabled:
            host = obj.extra.get("dns") or (obj.sam.rstrip("$") if obj.sam else "")
            if host:
                out.append((host, None))
    return out


def hosts_from_spec(spec):
    """Parse --hosts value: a file path (one host per line), a single host, or a
    comma-separated list. CIDR expansion is intentionally NOT done here (we want
    named hosts, not blind sweeps); a CIDR is passed through as-is for the caller
    to expand if desired."""
    import os
    out = []
    if os.path.isfile(spec):
        with open(spec) as fh:
            for line in fh:
                h = line.strip()
                if h and not h.startswith("#"):
                    out.append((h, None))
    else:
        for h in spec.split(","):
            h = h.strip()
            if h:
                out.append((h, None))
    return out
