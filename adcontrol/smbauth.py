"""
Shared SMB/DCE-RPC authentication helper for the GPO (SYSVOL) and per-host
(SAMR / remote-registry) planes.

Wraps the credential material once so gpo.py and hostrights.py connect the same
way as the LDAP layer: password, pass-the-hash, or Kerberos.
"""

from __future__ import annotations


def is_access_denied(exc: Exception) -> bool:
    """True if *exc* is an impacket DCERPC access-denied fault (error code 5,
    ``rpc_s_access_denied``) — the specific RPC method requires more than the
    scan account has (e.g. NetWkstaUserEnum/NetSessionEnum/SAMR/LSA calls all
    require local admin), distinct from an SMB login/auth failure."""
    try:
        from impacket.dcerpc.v5.rpcrt import DCERPCException
    except ImportError:
        return False
    return isinstance(exc, DCERPCException) and getattr(exc, "error_code", None) == 5


class SmbCreds:
    """Immutable-ish bundle of credentials + an impacket SMBConnection factory."""

    def __init__(self, username, password="", domain="", nthash="",
                 use_kerberos=False, aes_key="", dc_ip="", log=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash, self.nthash = self._split_hash(nthash)
        self.use_kerberos = use_kerberos or bool(aes_key)
        self.aes_key = aes_key
        self.dc_ip = dc_ip
        self._log = log or (lambda m, l="info": None)

    @staticmethod
    def _split_hash(h):
        h = (h or "").strip()
        if not h:
            return "", ""
        if ":" in h:
            lm, nt = h.split(":", 1)
            return (lm or "aad3b435b51404eeaad3b435b51404ee"), nt
        return "aad3b435b51404eeaad3b435b51404ee", h

    def log(self, msg, level="info"):
        self._log(msg, level)

    def connect(self, host, target_ip=None, timeout=8):
        """Return an authenticated impacket SMBConnection to *host*, or None."""
        from impacket.smbconnection import SMBConnection
        try:
            conn = SMBConnection(host, target_ip or host, timeout=timeout)
            if self.use_kerberos:
                conn.kerberosLogin(self.username, self.password, self.domain,
                                   self.lmhash, self.nthash, self.aes_key,
                                   kdcHost=self.dc_ip or None)
            else:
                conn.login(self.username, self.password, self.domain,
                           self.lmhash, self.nthash)
            return conn
        except Exception as e:
            self.log(f"[smb] {host}: {e}", "warn")
            return None
