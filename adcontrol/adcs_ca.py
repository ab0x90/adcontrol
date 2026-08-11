"""
CA-host registry plane (tier — OPT-IN, connects to each collected CA's own
host over SMB/RPC, not just the DC) — the only way to see ESC6/ESC7/ESC11/
ESC16, none of which are LDAP-readable AD attributes. They live in the CA's
own registry, under ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\
Configuration\\<CA-Name>\\...`` on the CA server itself:

  * ``EditFlags`` (under the active PolicyModule subkey)   -> ESC6
    (``EDITF_ATTRIBUTESUBJECTALTNAME2`` — CA-wide "enrollee can specify SAN").
  * ``DisableExtensionList`` (same key)                     -> ESC16
    (contains the SID security extension OID -> CA never issues it).
  * ``InterfaceFlags`` (the CA's own config key)             -> ESC11
    (``IF_ENFORCEENCRYPTICERTREQUEST`` NOT set -> ICPR/RPC requests aren't
    required to be encrypted, enabling NTLM relay to the CA's RPC interface).
  * ``Security`` (same key — a raw Windows SECURITY_DESCRIPTOR blob, but NOT
    an AD object DACL: the access-mask bits are ``CertificateAuthorityRights``
    — ManageCA/ManageCertificates/Enroll — a completely different vocabulary
    from AD's ACCESS_MASK, so this does NOT reuse sddl.py's AD-specific
    right-name mapping)                                      -> ESC7.

This mirrors exactly what certipy-ad's own ``CA.get_config_rrp()`` reads
(confirmed by reading its installed source) — same registry paths, same
values — but implemented directly against impacket's ``dcerpc.v5.rrp``
(Remote Registry Protocol) using this project's own SMB connection plane
(``smbauth.SmbCreds``, the same one hostrights.py/sessions.py/gpo.py use),
rather than depending on certipy-ad's own Target/CA class hierarchy at
runtime — keeps certipy-ad a purely optional dependency (used elsewhere only
for its flag-name constant tables) instead of a hard one.

Read access to these specific registry values has historically not required
local-admin on the CA host in many environments (unlike SAMR/LSA, which
hostrights.py already flags as commonly access-denied) — but failures here
are still per-CA and non-fatal, matching hostrights.py's per-host isolation.
"""

from __future__ import annotations

from adcontrol.smbauth import is_access_denied

# CertificateAuthorityRights bit values — the CA's OWN security-descriptor
# access-mask vocabulary (MS-CRTD / certsrv), unrelated to AD's ACCESS_MASK.
# Reused from certipy-ad when installed (same pattern as adcs.py's flag
# decoding); these 3 specific bits are small, stable, and Microsoft-
# documented, so a local fallback is safe here (unlike the much larger
# CT_FLAG_* tables adcs.py deliberately avoids hand-transcribing).
try:
    from certipy.lib.constants import CertificateAuthorityRights as _CARights
    _MANAGE_CA = int(_CARights.MANAGE_CA)
    _MANAGE_CERTIFICATES = int(_CARights.MANAGE_CERTIFICATES)
    _ENROLL = int(_CARights.ENROLL)
except Exception:
    _MANAGE_CA, _MANAGE_CERTIFICATES, _ENROLL = 1, 2, 512

# ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 bit in EditFlags.
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
# ESC11: IF_ENFORCEENCRYPTICERTREQUEST bit in InterfaceFlags — vulnerable
# when this bit is ABSENT (RPC requests aren't required to be encrypted).
IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200
# ESC16: the SID security extension OID, checked for membership in
# DisableExtensionList (a list of OID strings).
SZOID_NTDS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2"


def _reg_value(dce, hkey, name):
    from impacket.dcerpc.v5 import rrp
    _, val = rrp.hBaseRegQueryValue(dce, hkey, name)
    return val


def _read_ca_config_once(smb, host, ca_name):
    """One attempt at reading the CA's registry config via RRP. Raises on
    failure — retried by the caller."""
    from impacket.dcerpc.v5 import transport, rrp
    dce = None
    try:
        rpc = transport.SMBTransport(host, filename=r"\winreg", smb_connection=smb)
        dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(rrp.MSRPC_UUID_RRP)
        hklm = rrp.hOpenLocalMachine(dce)["phKey"]

        base = f"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca_name}"
        policy_root = rrp.hBaseRegOpenKey(dce, hklm, f"{base}\\PolicyModules")["phkResult"]
        active_policy = _reg_value(dce, policy_root, "Active")
        active_policy = (active_policy or "").strip("\x00") \
            or "CertificateAuthority_MicrosoftDefault.Policy"

        policy_key = rrp.hBaseRegOpenKey(
            dce, hklm, f"{base}\\PolicyModules\\{active_policy}")["phkResult"]
        edit_flags = _reg_value(dce, policy_key, "EditFlags")
        disable_ext_raw = _reg_value(dce, policy_key, "DisableExtensionList")

        config_key = rrp.hBaseRegOpenKey(dce, hklm, base)["phkResult"]
        interface_flags = _reg_value(dce, config_key, "InterfaceFlags")
        security_blob = _reg_value(dce, config_key, "Security")

        disabled_extensions = [x for x in (disable_ext_raw or "").strip("\x00").split("\x00") if x]
        return {
            "edit_flags": int(edit_flags) if isinstance(edit_flags, int) else 0,
            "interface_flags": int(interface_flags) if isinstance(interface_flags, int) else 0,
            "disabled_extensions": disabled_extensions,
            "security_blob": bytes(security_blob) if isinstance(security_blob, (bytes, bytearray)) else b"",
        }
    finally:
        if dce is not None:
            try:
                dce.disconnect()
            except Exception:
                pass


def _read_ca_config(smb, host, ca_name, log):
    """Read one CA's registry config via RRP. Returns a dict, or None if it
    genuinely couldn't be read.

    Retries ONCE after a short delay on failure: the Remote Registry service
    is "Manual (Trigger Start)" on modern Windows — the FIRST connection to
    \\winreg is what triggers it to start, and that very first attempt
    commonly fails with STATUS_PIPE_NOT_AVAILABLE while the service is still
    coming up; a retry a couple seconds later typically succeeds. Caught on
    real GOAD data: a bare single attempt failed with exactly that error even
    though the same CA host answered fine moments earlier via a separate
    certipy-ad run (which likely benefited from — or itself triggered — the
    same warm-up)."""
    import time
    for attempt in range(2):
        try:
            return _read_ca_config_once(smb, host, ca_name)
        except Exception as e:
            if is_access_denied(e):
                log(f"[ca] {host}: registry access denied for CA {ca_name!r} — scan "
                   "account likely isn't local admin on the CA host", "info")
                return None
            if attempt == 0:
                log(f"[ca] {host}: registry read failed for CA {ca_name!r} ({e}) — "
                   "retrying once (Remote Registry is often trigger-start and the "
                   "first connection can lose the race)", "info")
                time.sleep(2)
                continue
            log(f"[ca] {host}: registry read failed for CA {ca_name!r}: {e}", "warn")
            return None


def _parse_ca_security(blob):
    """Parse the CA's registry Security blob into (owner_sid, [(trustee_sid,
    [right_names])]) — CertificateAuthorityRights bits, not AD rights."""
    if not blob:
        return "", []
    from impacket.ldap import ldaptypes
    from adcontrol.sddl import _sid_str
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=blob)
    except Exception:
        return "", []
    owner = ""
    try:
        owner = _sid_str(sd["OwnerSid"].getData() if hasattr(sd["OwnerSid"], "getData")
                         else sd["OwnerSid"])
    except Exception:
        pass
    dacl = sd["Dacl"]
    out = []
    if not dacl or not getattr(dacl, "aces", None):
        return owner, out
    for ace in dacl.aces:
        # Only plain ALLOW ACEs — CertificateAuthorityRights never uses the
        # object-type (extended-right-GUID) ACE variants AD does.
        if ace["AceType"] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
            continue
        body = ace["Ace"]
        try:
            mask = int(body["Mask"]["Mask"])
        except Exception:
            continue
        sid = _sid_str(body["Sid"])
        names = []
        if mask & _MANAGE_CA:
            names.append("ManageCa")
        if mask & _MANAGE_CERTIFICATES:
            names.append("ManageCertificates")
        if mask & _ENROLL:
            names.append("Enroll")
        if names:
            out.append((sid, names))
    return owner, out


def check_web_enrollment(host, timeout=5) -> dict:
    """ESC8 exposure indicator: is the classic Web Enrollment endpoint
    (``/certsrv/``) reachable over plain HTTP? Just a GET — NOT the actual
    NTLM-relay attack (that needs live coercion+relay tooling, out of scope
    for an enumeration tool). Returns {'http': bool|None}; None on a network
    error (couldn't tell, not "confirmed absent")."""
    import http.client
    import socket
    try:
        conn = http.client.HTTPConnection(host, 80, timeout=timeout)
        conn.request("GET", "/certsrv/", headers={"Host": host})
        resp = conn.getresponse()
        # Any HTTP response (even 401/403) means the endpoint exists.
        enabled = resp.status < 500
        conn.close()
        return {"http": enabled}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"http": False}
    except Exception:
        return {"http": None}


def collect_ca_config(store, smb_creds, log=None, probe_web_enrollment=True) -> int:
    """Opt-in: connect to each collected CA's own host and read its registry
    config for ESC6/ESC7/ESC11/ESC16 (plus, unless disabled, an HTTP probe
    for the ESC8 exposure indicator). Populates ``ca.extra['ca_config']``;
    ESC analysis (adcs.py) reads it from there. Best-effort per CA — one
    unreachable/inaccessible CA never aborts the sweep."""
    log = log or smb_creds.log
    cas = [o for o in store.objects.values() if o.object_class == "pKIEnrollmentService"]
    if not cas:
        log("[ca] no CA objects collected — CA-registry plane skipped", "info")
        return 0
    added = 0
    for ca in cas:
        ca_name = ca.extra.get("cn") or ca.name
        host = ca.extra.get("dns") or ""
        if not host:
            log(f"[ca] CA {ca_name!r} has no dNSHostName collected — skipping", "info")
            continue
        log(f"[ca] -> {ca_name} ({host})", "info")

        # Registry portion (ESC6/7/11/16) and the HTTP web-enrollment probe
        # (ESC8) are INDEPENDENT — deliberately not gated on each other.
        # Bug caught on real GOAD data: the registry read can legitimately
        # fail (Remote Registry service not running — common on hardened
        # Windows) while the CA host is still perfectly reachable over HTTP;
        # an earlier version skipped the web-enrollment probe entirely
        # whenever the registry read failed, silently losing ESC8 for a
        # reason that had nothing to do with ESC8.
        raw = None
        smb = smb_creds.connect(host)
        if smb:
            raw = _read_ca_config(smb, host, ca_name, log)
            try:
                smb.close()
            except Exception:
                pass

        cfg = {"registry_collected": raw is not None,
               "edit_flags": 0, "interface_flags": 0, "disabled_extensions": [],
               "security_owner": "", "security_aces": []}
        if raw is not None:
            owner, sec_aces = _parse_ca_security(raw.pop("security_blob"))
            raw["security_owner"] = owner
            raw["security_aces"] = sec_aces
            cfg.update(raw)

        if probe_web_enrollment:
            cfg["web_enrollment"] = check_web_enrollment(host)

        ca.extra["ca_config"] = cfg
        added += 1
        log(f"[ca] done {ca_name} (registry={'ok' if cfg['registry_collected'] else 'failed'}, "
           f"web-enrollment probe={'ran' if probe_web_enrollment else 'skipped'})", "info")
    return added
