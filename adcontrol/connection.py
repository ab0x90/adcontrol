"""
LDAP connection + paged search for adcontrol.

Provides one class, :class:`LdapClient`,
that abstracts over two auth backends:

  * Kerberos  -> impacket ``LDAPConnection.kerberosLogin`` (handles TGT + service
                 ticket without gssapi), yields raw attribute dicts.
  * NTLM / PtH -> ldap3 ``Connection`` with automatic LDAP(389) -> LDAPS(636)
                 fallback, yields raw attribute dicts.

Both backends attach:
  * a paged-results control (AD caps a plain search at MaxPageSize ~1000), and
  * an **SD flags control with sdflags=0x07 (Owner|Group|DACL, no SACL)** so the
    DC returns ``nTSecurityDescriptor`` without the caller needing
    SeSecurityPrivilege (requesting the SACL bit would).

The search yields uniform records: ``{attr_name: value_or_list}`` with
``nTSecurityDescriptor`` as raw ``bytes`` and ``objectSid`` as canonical string.
"""

from __future__ import annotations

import ssl
import socket
import ipaddress

# sdflags = OWNER(0x1) | GROUP(0x2) | DACL(0x4) = 0x7  — deliberately no SACL(0x8)
SD_FLAGS = 0x07


def _base_dn_from_domain(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split(".") if p)


def _parse_hash(h: str) -> tuple[str, str]:
    """Return (lmhash, nthash) from 'LM:NT', ':NT', or 'NT'."""
    h = (h or "").strip()
    if not h:
        return "", ""
    if ":" in h:
        lm, nt = h.split(":", 1)
        return (lm or "aad3b435b51404eeaad3b435b51404ee"), nt
    return "aad3b435b51404eeaad3b435b51404ee", h


class LdapClient:
    def __init__(self, dc, username, password="", domain="", nthash="",
                 use_ldaps=False, use_kerberos=False, aes_key="", dc_ip="",
                 log=None):
        self.dc = dc
        self.username = username
        self.password = password
        self.domain = domain or self._domain_from_dc(dc)
        self.nthash = nthash
        self.use_ldaps = use_ldaps
        self.use_kerberos = use_kerberos or bool(aes_key)
        self.aes_key = aes_key
        self.dc_ip = dc_ip
        self.base_dn = _base_dn_from_domain(self.domain)
        self._log = log or (lambda m, l="info": None)
        self._impacket_conn = None
        self._ldap3_conn = None
        self._ldap3_server = None
        self._config_nc = ""

    def log(self, msg, level="info"):
        self._log(msg, level)

    @staticmethod
    def _domain_from_dc(dc):
        parts = dc.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else ""

    # -- connect --------------------------------------------------------------
    def connect(self) -> bool:
        if self.use_kerberos:
            return self._connect_kerberos()
        return self._connect_ntlm()

    def _resolve_dc_fqdn(self):
        dc, domain = self.dc, self.domain
        try:
            ipaddress.ip_address(dc)
            ip = dc
        except ValueError:
            if len(dc.split(".")) > len(domain.split(".")):
                return dc, (self.dc_ip or self._safe_gethostbyname(dc))
            ip = self._safe_gethostbyname(dc)
        if not ip:
            return dc, self.dc_ip
        try:
            names = socket.gethostbyaddr(ip)
            cands = [names[0]] + names[1]
            indom = [n for n in cands if n.lower().endswith("." + domain.lower())]
            indom.sort(key=lambda n: len(n.split(".")), reverse=True)
            return (indom[0] if indom else cands[0]), ip
        except Exception:
            return dc, ip

    @staticmethod
    def _safe_gethostbyname(h):
        try:
            return socket.gethostbyname(h)
        except Exception:
            return ""

    def _connect_kerberos(self) -> bool:
        try:
            from impacket.ldap import ldap as il
        except ImportError as e:
            self.log(f"[LDAP] impacket unavailable: {e}", "error")
            return False
        dc_fqdn, dc_ip = self._resolve_dc_fqdn()
        self.dc_ip = dc_ip or self.dc_ip
        lm, nt = _parse_hash(self.nthash)
        self.log(f"[LDAP] Kerberos bind to {dc_fqdn} as {self.domain}\\{self.username}", "info")
        try:
            conn = il.LDAPConnection(f"ldap://{dc_fqdn}", baseDN=self.base_dn,
                                     dstIp=self.dc_ip or None)
            conn.kerberosLogin(user=self.username, password=self.password,
                               domain=self.domain, lmhash=lm, nthash=nt,
                               aesKey=self.aes_key or "",
                               kdcHost=self.dc_ip or dc_fqdn, useCache=False)
        except Exception as e:
            self.log(f"[LDAP] Kerberos bind failed: {e}", "error")
            return False
        self._impacket_conn = conn
        self.log("[LDAP] Kerberos bind OK", "info")
        return True

    def _connect_ntlm(self) -> bool:
        from ldap3 import Server, Connection, NTLM, ALL, Tls
        nb = self.domain.split(".")[0].upper() if "." in self.domain else self.domain
        user_str = f"{nb}\\{self.username}" if nb else self.username
        if self.nthash:
            lm, nt = _parse_hash(self.nthash)
            secret = f"{lm}:{nt}"
        else:
            secret = self.password
        attempts = [(True, "LDAPS")] if self.use_ldaps else [(False, "LDAP"), (True, "LDAPS (fallback)")]
        last = None
        for ldaps, label in attempts:
            port = 636 if ldaps else 389
            try:
                self.log(f"[LDAP] {label} to {self.dc}:{port} as {user_str} (NTLM)", "info")
                if ldaps:
                    tls = Tls(validate=ssl.CERT_NONE)
                    srv = Server(self.dc, port=port, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=10)
                else:
                    srv = Server(self.dc, port=port, get_info=ALL, connect_timeout=10)
                c = Connection(srv, user=user_str, password=secret, authentication=NTLM, auto_bind=False)
                c.open(); c.bind()
                if c.bound:
                    self._ldap3_conn, self._ldap3_server = c, srv
                    if not self.base_dn:
                        try:
                            self.base_dn = str(srv.info.other.get("defaultNamingContext", [""])[0])
                        except Exception:
                            pass
                    self.log(f"[LDAP] Bound via {label}", "info")
                    return True
                last = f"bind rejected: {c.result}"
                c.unbind()
            except Exception as e:
                last = str(e)
                self.log(f"[LDAP] {label} failed: {e}", "info")
        self.log(f"[LDAP] All NTLM attempts failed. Last: {last}", "error")
        return False

    # -- Configuration NC -------------------------------------------------------
    def config_naming_context(self) -> str:
        """The forest's Configuration NC DN, read from the RootDSE.

        There is exactly ONE Configuration NC per forest, always rooted at the
        FOREST ROOT domain — never guessable from ``base_dn`` when the target is
        a child domain (e.g. binding to a DC of ``child.corp.local``, base_dn
        ``DC=child,DC=corp,DC=local``, the real Configuration NC is
        ``CN=Configuration,DC=corp,DC=local``, one level up — NOT
        ``CN=Configuration,DC=child,DC=corp,DC=local``, which doesn't exist and
        makes every Config-NC search — schema GUIDs, extended rights, and ADCS
        objects — silently return zero results). Cached after first
        successful fetch; falls back to the (possibly wrong) same-domain guess
        only if the RootDSE lookup itself fails, so collection still proceeds
        rather than hard-erroring."""
        if self._config_nc:
            return self._config_nc
        try:
            if self._impacket_conn is not None:
                self._config_nc = self._config_nc_impacket()
            else:
                self._config_nc = self._config_nc_ldap3()
        except Exception as e:
            self.log(f"[LDAP] RootDSE configurationNamingContext lookup failed: {e}", "info")
        if not self._config_nc:
            self._config_nc = f"CN=Configuration,{','.join(p for p in self.base_dn.split(',') if p.strip().upper().startswith('DC='))}"
            self.log("[LDAP] Could not read Configuration NC from RootDSE — falling back to a "
                     "same-domain guess (wrong if the target is a child domain in a multi-domain forest)", "warn")
        return self._config_nc

    def _config_nc_ldap3(self) -> str:
        try:
            vals = self._ldap3_server.info.other.get("configurationNamingContext")
            return str(vals[0]) if vals else ""
        except Exception:
            return ""

    def _config_nc_impacket(self) -> str:
        from impacket.ldap import ldapasn1 as la
        resp = self._impacket_conn.search(searchBase="", scope=0,
                                          searchFilter="(objectClass=*)",
                                          attributes=["configurationNamingContext"])
        for entry in resp or []:
            if not isinstance(entry, la.SearchResultEntry):
                continue
            for attr in entry["attributes"]:
                if str(attr["type"]) == "configurationNamingContext":
                    vals = attr["vals"]
                    if vals:
                        return str(vals[0])
        return ""

    # -- search ---------------------------------------------------------------
    def search(self, search_filter, attributes, base=None, want_sd=True):
        """Yield uniform attribute dicts for matching entries."""
        base = base or self.base_dn
        if self._impacket_conn is not None:
            yield from self._search_impacket(search_filter, attributes, base, want_sd)
        else:
            yield from self._search_ldap3(search_filter, attributes, base, want_sd)

    def _search_impacket(self, search_filter, attributes, base, want_sd):
        from impacket.ldap import ldap as il, ldapasn1 as la
        from impacket.ldap.ldapasn1 import SimplePagedResultsControl, SDFlagsControl
        controls = [SimplePagedResultsControl(criticality=True, size=1000, cookie="")]
        if want_sd:
            controls.append(SDFlagsControl(criticality=True, flags=SD_FLAGS))
        try:
            resp = self._impacket_conn.search(searchBase=base, searchFilter=search_filter,
                                              attributes=attributes, searchControls=controls)
        except il.LDAPSearchError as e:
            if "sizeLimitExceeded" in str(e):
                self.log("[LDAP] sizeLimitExceeded — partial results", "warn")
                resp = e.getAnswers()
            else:
                self.log(f"[LDAP] search failed: {e}", "error")
                return
        except Exception as e:
            self.log(f"[LDAP] search failed: {e}", "error")
            return
        for entry in resp or []:
            if not isinstance(entry, la.SearchResultEntry):
                continue
            rec = {}
            for attr in entry["attributes"]:
                atype = str(attr["type"])
                vals = attr["vals"]
                if atype == "nTSecurityDescriptor":
                    rec[atype] = bytes(vals[0]) if vals else b""
                elif atype == "objectSid":
                    from impacket.ldap.ldaptypes import LDAP_SID
                    rec[atype] = LDAP_SID(data=bytes(vals[0])).formatCanonical() if vals else ""
                elif atype == "objectGUID":
                    from impacket.uuid import bin_to_string
                    rec[atype] = bin_to_string(bytes(vals[0])).lower() if vals else ""
                else:
                    out = [str(v) for v in vals]
                    rec[atype] = out if len(out) != 1 else out[0]
            yield rec

    def _search_ldap3(self, search_filter, attributes, base, want_sd):
        from ldap3 import SUBTREE
        from ldap3.protocol.microsoft import security_descriptor_control
        controls = security_descriptor_control(sdflags=SD_FLAGS) if want_sd else None
        try:
            entries = self._ldap3_conn.extend.standard.paged_search(
                search_base=base, search_filter=search_filter, search_scope=SUBTREE,
                attributes=attributes, paged_size=1000, generator=True, controls=controls,
            )
        except Exception as e:
            self.log(f"[LDAP] search failed: {e}", "error")
            return
        for entry in entries:
            if entry.get("type") != "searchResEntry":
                continue
            raw = entry.get("raw_attributes", {})
            attrs = entry.get("attributes", {})
            rec = {}
            for k, v in attrs.items():
                rec[k] = v[0] if isinstance(v, list) and len(v) == 1 else v
            # nTSecurityDescriptor and objectSid must come from raw bytes.
            if "nTSecurityDescriptor" in raw and raw["nTSecurityDescriptor"]:
                rec["nTSecurityDescriptor"] = bytes(raw["nTSecurityDescriptor"][0])
            if "objectSid" in raw and raw["objectSid"]:
                from impacket.ldap.ldaptypes import LDAP_SID
                rec["objectSid"] = LDAP_SID(data=bytes(raw["objectSid"][0])).formatCanonical()
            rec["dn"] = entry.get("dn", "")
            yield rec

    def close(self):
        try:
            if self._ldap3_conn:
                self._ldap3_conn.unbind()
        except Exception:
            pass
