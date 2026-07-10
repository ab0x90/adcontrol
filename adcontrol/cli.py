#!/usr/bin/env python3
"""
adcontrol — Active Directory object-control / permission analyzer.

Maps, for a chosen principal, every object it can control across the domain
(outbound) and every principal that can control it (inbound), derived from AD
object DACLs, transitive group membership, GPO-delivered rights, and (optionally)
per-host RDP/logon rights.

Standalone, self-contained tool.

  GUI (default):
    python3 -m adcontrol --dc dc01.corp.local -u user -p pass -d corp.local
    # or, after `pip install .`:  adcontrol --dc ...

  CLI (collect + print/report one principal, no web server):
    python3 -m adcontrol --dc dc01.corp.local -u user -p pass -d corp.local \\
        --nogui --subject alice --report out.html
"""

import sys
import socket
import argparse


def _log(msg, level="info"):
    colors = {"error": "\033[31m", "warn": "\033[33m", "info": "\033[90m"}
    print(f"{colors.get(level,'')}{msg}\033[0m")


def _derive_dc(domain: str) -> str:
    """Best-effort discovery of a DC host when --dc was not given but a domain
    was. Tries the AD DC-locator SRV record, then falls back to resolving the
    domain name itself (the domain usually resolves to its DCs). Returns a
    hostname/IP, or "" if nothing resolves."""
    if not domain:
        return ""
    # 1. SRV lookup: _ldap._tcp.dc._msdcs.<domain>
    try:
        import dns.resolver  # dnspython, if available
        ans = dns.resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV")
        targets = sorted(ans, key=lambda r: (r.priority, -r.weight))
        if targets:
            return str(targets[0].target).rstrip(".")
    except Exception:
        pass
    # 2. Fall back to resolving the domain name directly.
    try:
        socket.gethostbyname(domain)
        return domain
    except Exception:
        return ""


def cli_mode(args):
    from adcontrol.connection import LdapClient
    from adcontrol import collector as collector_mod
    from adcontrol.analyze import Analyzer
    from adcontrol import report as report_mod
    from adcontrol.smbauth import SmbCreds
    from adcontrol import hostrights as hr_mod

    client = LdapClient(dc=args.dc, username=args.username, password=args.password or "",
                        domain=args.domain, nthash=args.nthash or "",
                        use_ldaps=args.ldaps, use_kerberos=args.kerberos,
                        aes_key=args.aes_key or "", dc_ip=args.dc_ip or "", log=_log)
    if not client.connect():
        sys.exit("connection failed")

    # SMB creds for the GPO (tier 2) and host (tier 3) planes. Only built if any
    # SMB-touching plane is active.
    do_gpo = not args.no_gpo
    host_targets = None
    smb_creds = None
    if do_gpo or args.host_rights or args.hosts:
        smb_creds = SmbCreds(username=args.username, password=args.password or "",
                             domain=client.domain, nthash=args.nthash or "",
                             use_kerberos=args.kerberos, aes_key=args.aes_key or "",
                             dc_ip=args.dc_ip or client.dc_ip or "", log=_log)

    store = collector_mod.collect(client, log=_log, smb_creds=smb_creds,
                                  dc_host=args.dc, dc_ip=args.dc_ip or client.dc_ip or "",
                                  do_gpo=do_gpo, host_targets=None)
    client.close()

    # Tier 3 host plane (opt-in). Resolve targets AFTER LDAP so --host-rights can
    # use collected computers.
    if args.hosts:
        host_targets = hr_mod.hosts_from_spec(args.hosts)
    elif args.host_rights:
        host_targets = hr_mod.hosts_from_store(store)
    if host_targets and smb_creds:
        hr_mod.collect_host_rights(store, smb_creds, host_targets, log=_log)

    _analyze_store(store, args)


def _analyze_store(store, args):
    """Print (and optionally report) the analysis for args.subject. Shared by the
    live scan and the BloodHound-import CLI paths."""
    from adcontrol.analyze import Analyzer
    from adcontrol import report as report_mod

    if not args.subject:
        print(f"\nLoaded {len(store)} objects / {len(store.principals())} principals.")
        print("Re-run with --subject <name> to analyze a principal.")
        return

    matches = store.find(args.subject)
    matches = [m for m in matches if m.object_class in ("user", "group", "computer")]
    if not matches:
        sys.exit(f"no principal matching '{args.subject}'")
    subj = matches[0]
    az = Analyzer(store)
    s = az.summarize(subj)
    print(f"\n=== {subj.label} ({subj.object_class}) ===")
    print(f"Outbound: {len(s['outbound'])} edges ({s['outbound_high']} high) | "
          f"Inbound: {len(s['inbound'])} edges ({s['inbound_high']} high)\n")
    print("-- OUTBOUND (can control) --")
    for e in s["outbound"]:
        print(f"  [{e.severity:6}] {e.right:35} -> {e.target_label} ({e.target_class}) via {e.via}")
    print("\n-- INBOUND (controlled by) --")
    for e in s["inbound"]:
        b = " [BROAD]" if e.broad else ""
        print(f"  [{e.severity:6}] {e.source_label:30} : {e.right}{b}")

    if s["policy_rights"]:
        print("\n-- GPO / HOST RDP & LOGON RIGHTS --")
        for pr in s["policy_rights"]:
            print(f"  [{pr.severity:6}] ({pr.plane}) {pr.right}  applies: {pr.applies_to}")

    if args.report:
        fmt = "md" if args.report.lower().endswith(".md") else "html"
        body = (report_mod.to_markdown if fmt == "md" else report_mod.to_html)(store, subj, az)
        with open(args.report, "w") as fh:
            fh.write(body)
        print(f"\nReport written: {args.report}")


def main():
    p = argparse.ArgumentParser(description="AD object-control / permission analyzer")
    p.add_argument("--bloodhound", dest="bloodhound",
                   help="Offline: import a BloodHound zip / json / directory instead of "
                        "scanning live. All analysis works the same on the imported data.")
    p.add_argument("--dc", help="Domain controller host/IP")
    p.add_argument("-u", "--username")
    p.add_argument("-p", "--password")
    p.add_argument("-d", "--domain", default="")
    p.add_argument("--nthash", help="NT hash for pass-the-hash (LM:NT / :NT / NT)")
    p.add_argument("-k", "--kerberos", action="store_true")
    p.add_argument("--aes-key", dest="aes_key")
    p.add_argument("--dc-ip", dest="dc_ip")
    p.add_argument("--ldaps", action="store_true", help="Force LDAPS")
    p.add_argument("--no-gpo", dest="no_gpo", action="store_true",
                   help="Skip the GPO plane (tier 2). Default: GPO rights are read "
                        "from the DC's SYSVOL only — no member host is touched.")
    p.add_argument("--host-rights", dest="host_rights", action="store_true",
                   help="Tier 3: query local RDP/admin membership on ALL collected "
                        "computers via SAMR+LSA (fans out to every host — noisy).")
    p.add_argument("--hosts", dest="hosts",
                   help="Tier 3: query only these hosts (file, single host, or "
                        "comma-separated list). Overrides --host-rights scope.")
    p.add_argument("--nogui", action="store_true", help="CLI only, no web server")
    p.add_argument("--subject", help="(CLI) principal to analyze")
    p.add_argument("--report", help="(CLI) write report to this path (.html or .md)")
    p.add_argument("--host", default="127.0.0.1", help="GUI bind host")
    p.add_argument("--port", type=int, default=5006, help="GUI port (default 5006)")
    args = p.parse_args()

    # If no DC was given but a domain was, try to discover one so the user does
    # not have to specify both.
    if not args.dc and args.domain:
        derived = _derive_dc(args.domain)
        if derived:
            args.dc = derived
            print(f"[dc] no --dc given; using {derived} discovered from domain {args.domain}")
        else:
            print(f"[dc] no --dc given and could not discover a DC for {args.domain}; "
                  f"pass --dc <host/IP>")

    # Offline BloodHound import short-circuits the live scan entirely.
    if args.bloodhound:
        from adcontrol import bloodhound as bh_mod
        store = bh_mod.import_zip(args.bloodhound, log=_log)
        if args.nogui:
            _analyze_store(store, args)
        else:
            from adcontrol.app import run
            print(f"adcontrol GUI (BloodHound: {args.bloodhound}) → http://{args.host}:{args.port}")
            run(host=args.host, port=args.port, preloaded_store=store)
        return

    if args.nogui:
        if not (args.dc and args.username):
            p.error("--nogui requires --dc (or a resolvable --domain) and --username")
        cli_mode(args)
    else:
        from adcontrol.app import run
        # Carry any CLI-supplied connection details into the GUI so the collect
        # form is pre-filled, and auto-start collection when we have enough to
        # connect (a DC + username + some secret / kerberos).
        prefill = {
            "dc": args.dc or "", "username": args.username or "",
            "domain": args.domain or "", "password": args.password or "",
            "nthash": args.nthash or "", "kerberos": bool(args.kerberos),
            "ldaps": bool(args.ldaps), "aes_key": args.aes_key or "",
            "dc_ip": args.dc_ip or "", "gpo": not args.no_gpo,
            "host_mode": ("list" if args.hosts else ("all" if args.host_rights else "none")),
            "hosts": args.hosts or "",
        }
        have_secret = bool(args.password or args.nthash or args.kerberos or args.aes_key)
        prefill["autostart"] = bool(args.dc and args.username and have_secret)
        if prefill["autostart"]:
            print("adcontrol GUI → collection will auto-start with the supplied credentials")
        print(f"adcontrol GUI → http://{args.host}:{args.port}")
        run(host=args.host, port=args.port, prefill=prefill)


if __name__ == "__main__":
    main()
