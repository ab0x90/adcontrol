#!/usr/bin/env python3
"""
adcontrol Scan — credentialed AD object-control / permission gatherer.

Runs ALL collection/enumeration (AD object ACLs, ADCS templates, GPO-delivered
rights, per-host RDP/local-admin, live logon sessions) OR imports an existing
BloodHound/SharpHound collection, and writes the result to its own directory
under loot/<run_id>/ so that `adcontrol_web.py` (a separate process, run
afterwards, possibly on a separate host) can load and analyze/report on it.

This script has no web server or reporting capability of its own — it only
gathers and shows a live terminal dashboard while doing so.

Usage:
  # Live collection (tier 1 + ADCS + GPO by default; DC only)
  python3 adcontrol_scan.py --dc dc01.corp.local -u user -p pass -d corp.local

  # Add tier 3 (touches every collected host — noisy)
  python3 adcontrol_scan.py --dc dc01.corp.local -u user -p pass -d corp.local \\
      --host-rights --sessions --adcs-ca-config

  # Kerberos / pass-the-hash
  python3 adcontrol_scan.py --dc dc01.corp.local -u user -p pass -d corp.local -k
  python3 adcontrol_scan.py --dc dc01.corp.local -u user --nthash <NT> -d corp.local

  # Offline: import a BloodHound/SharpHound collection instead of scanning live
  python3 adcontrol_scan.py --bloodhound collection.zip

  # Offline report: generate a standalone HTML report from an existing loot run
  python3 adcontrol_scan.py --offline-report                  # latest run
  python3 adcontrol_scan.py --offline-report 20260811_143022  # specific run ID
  python3 adcontrol_scan.py --offline-report loot/20260811_143022/  # explicit path
"""

import argparse
import os
import re
import socket
import sys
import threading
import time
from collections import deque
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from adcontrol import loot

_ROOT = os.path.dirname(os.path.abspath(__file__))

console = Console()


def banner():
    console.print(r"""
[bold cyan]           _                _             _
  __ _  __| | ___ ___  _ __ | |_ _ __ ___ | |
 / _` |/ _` |/ __/ _ \| '_ \| __| '__/ _ \| |
| (_| | (_| | (_| (_) | | | | |_| | | (_) | |
 \__,_|\__,_|\___\___/|_| |_|\__|_|  \___/|_|[/]
[dim]      Scan  →  Loot  →  Web/Report  (scan-only, no GUI)[/]
""")


def _log_color(msg, level="info"):
    colors = {"error": "\033[31m", "warn": "\033[33m", "info": "\033[90m"}
    print(f"{colors.get(level,'')}{msg}\033[0m")


def _derive_dc(domain: str) -> str:
    """Best-effort discovery of a DC host when --dc was not given but a domain
    was. Tries the AD DC-locator SRV record, then falls back to resolving the
    domain name itself."""
    if not domain:
        return ""
    try:
        import dns.resolver
        ans = dns.resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV")
        targets = sorted(ans, key=lambda r: (r.priority, -r.weight))
        if targets:
            return str(targets[0].target).rstrip(".")
    except Exception:
        pass
    try:
        socket.gethostbyname(domain)
        return domain
    except Exception:
        return ""


# ── log-line patterns the dashboard understands (structured hooks would touch
#    every collection module; the library already logs everything it does, so
#    we read that instead — same approach ShareHunter's scan dashboard uses). ──
_RE_CONNECTED = re.compile(r"^\[LDAP\] (Bound via|Kerberos bind OK)")
_RE_SCHEMA_START = re.compile(r"^\[collect\] mapping schema")
_RE_SCHEMA_DONE = re.compile(r"^\[collect\] schema/rights GUID names: (\d+)")
_RE_OBJ_START = re.compile(r"^\[collect\] pulling objects")
_RE_OBJ_TICK = re.compile(r"^\[collect\]\s+(\d+) objects\.\.\.$")
_RE_OBJ_DONE = re.compile(r"^\[collect\] done: (\d+) objects, domain SID (\S+)")
_RE_ADCS_DONE = re.compile(r"^\[adcs\] collected (\d+) certificate template")
_RE_GPO_START = re.compile(r"^\[gpo\] reading (\d+) GPO")
_RE_GPO_DONE = re.compile(r"^\[gpo\] collected (\d+) GPO-delivered right")
_RE_HOST_START = re.compile(r"^\[host\] querying (\d+) host")
_RE_HOST_INFLIGHT = re.compile(r"^\[host\] -> (.+)$")
_RE_HOST_HOSTDONE = re.compile(r"^\[host\] done (.+)$")
_RE_HOST_DONE = re.compile(r"^\[host\] collected (\d+) per-host right")
_RE_SESS_START = re.compile(r"^\[sess\] enumerating logon sessions on (\d+) host")
_RE_SESS_INFLIGHT = re.compile(r"^\[sess\] -> (.+)$")
_RE_SESS_HOSTDONE = re.compile(r"^\[sess\] done (.+)$")
_RE_SESS_DONE = re.compile(r"^\[sess\] collected (\d+) logon session")

_STAGE_LABEL = {
    "connect": "Connecting",
    "schema": "Mapping schema / rights GUIDs",
    "objects": "Pulling AD objects + ACLs",
    "adcs": "ADCS certificate templates",
    "gpo": "GPO-delivered rights (SYSVOL)",
    "host": "Per-host RDP/local-admin (tier 3)",
    "sess": "Live logon sessions (tier 3)",
    "done": "Done",
}


class Dashboard:
    """Terminal progress state, updated by reading the library's own log
    messages (see the _RE_* patterns above) and rendered on a timer via
    rich.Live."""

    def __init__(self, header_lines: list, log_fh):
        self.header_lines = header_lines
        self.log_fh = log_fh
        self.start_time = time.time()

        self.lock = threading.Lock()
        self.stage = "connect"
        self.objects = 0
        self.schema_names = 0
        self.adcs_objects = 0
        self.gpo_total = 0
        self.gpo_rights = 0
        self.host_total = 0
        self.host_rights = 0
        self.host_inflight: set[str] = set()
        self.host_done_count = 0
        self.sess_total = 0
        self.sessions = 0
        self.sess_inflight: set[str] = set()
        self.sess_done_count = 0
        self.domain_sid = ""
        self.recent_logs = deque(maxlen=8)
        self.errors = deque(maxlen=6)
        self.done = False

    def log_callback(self, msg: str, level: str = "info"):
        self.log_fh.write(f"[{level}] {msg}\n")
        with self.lock:
            self.recent_logs.appendleft((level, msg))
            if level in ("warn", "error"):
                self.errors.appendleft(msg)

            if _RE_CONNECTED.search(msg):
                self.stage = "connect-ok"
            elif _RE_SCHEMA_START.search(msg):
                self.stage = "schema"
            elif (m := _RE_SCHEMA_DONE.search(msg)):
                self.schema_names = int(m.group(1))
            elif _RE_OBJ_START.search(msg):
                self.stage = "objects"
            elif (m := _RE_OBJ_TICK.search(msg)):
                self.objects = int(m.group(1))
            elif (m := _RE_OBJ_DONE.search(msg)):
                self.objects = int(m.group(1))
                self.domain_sid = m.group(2)
                self.stage = "adcs"
            elif (m := _RE_ADCS_DONE.search(msg)):
                self.adcs_objects = int(m.group(1))
            elif (m := _RE_GPO_START.search(msg)):
                self.stage = "gpo"
                self.gpo_total = int(m.group(1))
            elif (m := _RE_GPO_DONE.search(msg)):
                self.gpo_rights = int(m.group(1))
            elif (m := _RE_HOST_START.search(msg)):
                self.stage = "host"
                self.host_total = int(m.group(1))
            elif (m := _RE_HOST_INFLIGHT.search(msg)):
                self.host_inflight.add(m.group(1))
            elif (m := _RE_HOST_HOSTDONE.search(msg)):
                self.host_inflight.discard(m.group(1))
                self.host_done_count += 1
            elif (m := _RE_HOST_DONE.search(msg)):
                self.host_rights = int(m.group(1))
            elif (m := _RE_SESS_START.search(msg)):
                self.stage = "sess"
                self.sess_total = int(m.group(1))
            elif (m := _RE_SESS_INFLIGHT.search(msg)):
                self.sess_inflight.add(m.group(1))
            elif (m := _RE_SESS_HOSTDONE.search(msg)):
                self.sess_inflight.discard(m.group(1))
                self.sess_done_count += 1
            elif (m := _RE_SESS_DONE.search(msg)):
                self.sessions = int(m.group(1))

    def mark_done(self):
        with self.lock:
            self.done = True
            self.stage = "done"

    def render(self):
        elapsed = time.time() - self.start_time
        with self.lock:
            stage = self.stage
            objects = self.objects
            recent = list(self.recent_logs)
            errors = list(self.errors)
            host_inflight = sorted(self.host_inflight)[:6]
            sess_inflight = sorted(self.sess_inflight)[:6]

        header = Text()
        for i, line in enumerate(self.header_lines):
            if i:
                header.append("\n")
            header.append(line)

        stage_label = _STAGE_LABEL.get(stage, stage)
        if stage == "connect-ok":
            stage_label = _STAGE_LABEL["objects"]

        progress = Progress(
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=None),
            TimeElapsedColumn(),
        )
        progress.add_task(stage_label, total=None)

        stats = Table.grid(padding=(0, 2))
        stats.add_row(Text("Objects", style="cyan"), Text(str(objects), style="bold cyan"))
        stats.add_row(Text("Schema/rights GUIDs", style="cyan"), Text(str(self.schema_names)))
        stats.add_row(Text("ADCS objects", style="magenta"), Text(str(self.adcs_objects)))
        if self.gpo_total:
            stats.add_row(Text("GPOs read", style="yellow"), Text(str(self.gpo_total)))
            stats.add_row(Text("GPO-delivered rights", style="yellow"), Text(str(self.gpo_rights)))
        if self.host_total:
            stats.add_row(Text("Hosts (tier 3 admin/RDP)", style="green"),
                          Text(f"{self.host_done_count}/{self.host_total}"))
            stats.add_row(Text("Host-rights findings", style="green"), Text(str(self.host_rights)))
        if self.sess_total:
            stats.add_row(Text("Hosts (tier 3 sessions)", style="green"),
                          Text(f"{self.sess_done_count}/{self.sess_total}"))
            stats.add_row(Text("Logon sessions found", style="green"), Text(str(self.sessions)))

        inflight_lines = []
        if host_inflight:
            inflight_lines.append("admin/RDP: " + ", ".join(host_inflight))
        if sess_inflight:
            inflight_lines.append("sessions: " + ", ".join(sess_inflight))
        inflight_txt = Text("\n".join(inflight_lines) if inflight_lines else "(none)", style="cyan")

        top = Table.grid(expand=True)
        top.add_column(ratio=2)
        top.add_column(ratio=1)
        top.add_row(
            Panel(stats, title="Collected so far", border_style="magenta"),
            Panel(inflight_txt, title="In-flight hosts (tier 3)", border_style="cyan"),
        )

        log_tbl = Table(show_header=False, expand=True, box=None)
        log_tbl.add_column("msg", overflow="fold")
        colors = {"error": "red", "warn": "yellow", "info": "dim"}
        for level, msg in recent:
            log_tbl.add_row(Text(msg, style=colors.get(level, "")))
        if not recent:
            log_tbl.add_row(Text("(waiting for output...)", style="dim"))

        pieces = [
            Panel(header, title="adcontrol Scan", border_style="blue"),
            progress,
            top,
            Panel(log_tbl, title="Recent log", border_style="green"),
        ]
        if errors:
            err_txt = Text("\n".join(errors), style="red")
            pieces.append(Panel(err_txt, title="Recent warnings/errors", border_style="red"))

        return Group(*pieces)

    def print_summary(self, run_id, run_dir, store):
        elapsed = timedelta(seconds=int(time.time() - self.start_time))
        tbl = Table(title="Scan summary")
        tbl.add_column("Metric")
        tbl.add_column("Value")
        tbl.add_row("Objects", str(len(store)))
        tbl.add_row("Principals (user/group/computer)", str(len(store.principals())))
        tbl.add_row("Domain", store.domain or "")
        tbl.add_row("Domain SID", store.domain_sid or "")
        tbl.add_row("ADCS objects", str(self.adcs_objects))
        if self.gpo_total:
            tbl.add_row("GPO-delivered rights", str(self.gpo_rights))
        if self.host_total:
            tbl.add_row("Host-rights findings (tier 3)", str(self.host_rights))
        if self.sess_total:
            tbl.add_row("Logon sessions (tier 3)", str(self.sessions))
        tbl.add_row("Elapsed", str(elapsed))
        tbl.add_row("Run ID", run_id)
        tbl.add_row("Loot dir", run_dir)
        console.print(tbl)


def _default_log_path(run_dir: str) -> str:
    return os.path.join(run_dir, "scan.log")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="adcontrol Scan — AD object-control/permission gatherer (scan-only, no web GUI)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--bloodhound", metavar="PATH",
                    help="Offline: import a BloodHound zip/json/directory instead of "
                         "scanning live. Gathering only — no analysis is run here.")
    p.add_argument("--offline-report", dest="offline_report", metavar="RUN_ID_OR_PATH",
                    nargs="?", const="",
                    help="Generate a standalone HTML report from an existing loot run "
                         "and exit. No scan or import is performed. Accepts a run ID, "
                         "a loot directory path, or nothing (uses the most recent run).")
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
    p.add_argument("--sessions", dest="sessions", action="store_true",
                    help="Tier 3: enumerate live logon sessions on ALL collected "
                         "computers (fans out — enables HasSession attack paths).")
    p.add_argument("--session-hosts", dest="session_hosts",
                    help="Tier 3: enumerate logon sessions only on these hosts "
                         "(file, single host, or comma-separated list).")
    p.add_argument("--adcs-ca-config", dest="adcs_ca_config", action="store_true",
                    help="Tier 3: connect to each collected CA's own host (SMB+RRP, "
                         "not the DC) to read its registry config — the only way to "
                         "see ESC6/ESC7/ESC11/ESC16 (EditFlags/CA security descriptor/"
                         "InterfaceFlags/DisableExtensionList aren't LDAP attributes). "
                         "Also probes each CA's Web Enrollment endpoint over plain HTTP "
                         "for the ESC8 exposure indicator.")
    p.add_argument("--loot-dir", default=os.path.join(_ROOT, "loot"),
                    help="Base directory for run output (each run gets its own subdir)")
    return p


def _run_live(args, run_id, run_dir):
    from adcontrol.connection import LdapClient
    from adcontrol import collector as collector_mod
    from adcontrol.smbauth import SmbCreds
    from adcontrol import hostrights as hr_mod

    header_lines = [
        f"DC:      {args.dc}",
        f"Domain:  {args.domain or '(from DC)'}",
        f"User:    {args.username}",
        f"Tiers:   GPO={'on' if not args.no_gpo else 'off'}  "
        f"host-rights={'list' if args.hosts else ('all' if args.host_rights else 'off')}  "
        f"sessions={'list' if args.session_hosts else ('all' if args.sessions else 'off')}  "
        f"adcs-ca-config={'on' if args.adcs_ca_config else 'off'}",
        f"Run:     {run_id}",
    ]
    log_fh = open(_default_log_path(run_dir), "a", encoding="utf-8", buffering=1)
    dashboard = Dashboard(header_lines, log_fh)

    result = {"store": None, "error": None}

    def worker():
        try:
            client = LdapClient(dc=args.dc, username=args.username, password=args.password or "",
                                domain=args.domain, nthash=args.nthash or "",
                                use_ldaps=args.ldaps, use_kerberos=args.kerberos,
                                aes_key=args.aes_key or "", dc_ip=args.dc_ip or "",
                                log=dashboard.log_callback)
            if not client.connect():
                dashboard.log_callback("[collect] connection failed — aborting", "error")
                result["error"] = "connection failed"
                return

            do_gpo = not args.no_gpo
            smb_creds = None
            if (do_gpo or args.host_rights or args.hosts or args.sessions
                    or args.session_hosts or args.adcs_ca_config):
                smb_creds = SmbCreds(username=args.username, password=args.password or "",
                                     domain=client.domain, nthash=args.nthash or "",
                                     use_kerberos=args.kerberos, aes_key=args.aes_key or "",
                                     dc_ip=args.dc_ip or client.dc_ip or "",
                                     log=dashboard.log_callback)

            store = collector_mod.collect(client, log=dashboard.log_callback, smb_creds=smb_creds,
                                          dc_host=args.dc, dc_ip=args.dc_ip or client.dc_ip or "",
                                          do_gpo=do_gpo, host_targets=None)
            client.close()

            if args.hosts:
                host_targets = hr_mod.hosts_from_spec(args.hosts)
            elif args.host_rights:
                host_targets = hr_mod.hosts_from_store(store)
            else:
                host_targets = None
            if host_targets and smb_creds:
                hr_mod.collect_host_rights(store, smb_creds, host_targets, log=dashboard.log_callback)

            if args.session_hosts:
                session_targets = hr_mod.hosts_from_spec(args.session_hosts)
            elif args.sessions:
                session_targets = hr_mod.hosts_from_store(store)
            else:
                session_targets = None
            if session_targets and smb_creds:
                from adcontrol import sessions as sess_mod
                sess_mod.collect_sessions(store, smb_creds, session_targets, log=dashboard.log_callback)

            if args.adcs_ca_config and smb_creds:
                from adcontrol import adcs_ca as adcs_ca_mod
                adcs_ca_mod.collect_ca_config(store, smb_creds, log=dashboard.log_callback)

            result["store"] = store
        except Exception as e:
            dashboard.log_callback(f"[collect] fatal error: {e}", "error")
            result["error"] = str(e)
        finally:
            dashboard.mark_done()

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    try:
        with Live(dashboard.render(), console=console, refresh_per_second=4, screen=False) as live:
            while t.is_alive():
                live.update(dashboard.render())
                time.sleep(0.25)
            live.update(dashboard.render())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — in-flight host will finish, then aborting.[/]")
    t.join()
    log_fh.close()

    if result["error"] or result["store"] is None:
        console.print(f"[red]Scan failed: {result['error'] or 'unknown error'}[/]")
        sys.exit(1)

    return dashboard, result["store"]


def _run_bloodhound_import(args, run_id, run_dir):
    from adcontrol import bloodhound as bh_mod

    console.print(f"[*] Importing BloodHound data from {args.bloodhound} ...")
    t0 = time.time()
    store = bh_mod.import_zip(args.bloodhound, log=_log_color)
    dt = time.time() - t0

    tbl = Table(title="Import summary")
    tbl.add_column("Metric")
    tbl.add_column("Value")
    tbl.add_row("Source", args.bloodhound)
    tbl.add_row("Objects", str(len(store)))
    tbl.add_row("Principals (user/group/computer)", str(len(store.principals())))
    tbl.add_row("Domain", store.domain or "")
    tbl.add_row("Sessions", str(len(store.sessions)))
    tbl.add_row("Elapsed", f"{dt:.1f}s")
    tbl.add_row("Run ID", run_id)
    tbl.add_row("Loot dir", run_dir)
    console.print(tbl)
    return store


def _run_offline_report(args):
    from adcontrol import report_domain as rd_mod

    spec = args.offline_report  # "" = latest; otherwise a run ID or explicit path

    if spec:
        if os.path.isdir(spec) and os.path.isfile(os.path.join(spec, "store.pkl")):
            run_dir = spec
        else:
            run_dir = loot.run_dir_for(_ROOT, spec)
            if run_dir is None:
                console.print(f"[red]No loot run found for '{spec}' — check loot/ for valid run IDs.[/]")
                sys.exit(1)
    else:
        latest = loot.latest_run(_ROOT)
        if not latest:
            console.print("[red]No completed runs found in loot/ — run a scan first.[/]")
            sys.exit(1)
        run_dir = loot.run_dir_for(_ROOT, latest["run_id"])

    console.print(f"[*] Loading loot from {run_dir} ...")
    store = loot.load_store(run_dir)
    console.print(f"[*] Generating offline report ({len(store)} objects, domain {store.domain or '?'}) ...")

    html_content = rd_mod.to_html(store)
    out_path = os.path.join(run_dir, "report.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)

    console.print(f"\n[bold green]Report saved:[/] {out_path}")
    console.print(f"[dim]Open with: xdg-open \"{out_path}\"[/]")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.offline_report is not None:
        banner()
        _run_offline_report(args)
        return

    if args.aes_key:
        args.kerberos = True

    if not args.dc and args.domain and not args.bloodhound:
        derived = _derive_dc(args.domain)
        if derived:
            args.dc = derived
            console.print(f"[*] no --dc given; using {derived} discovered from domain {args.domain}")

    if not args.bloodhound:
        if not args.dc:
            parser.error("--dc (or a resolvable --domain) is required for a live scan")
        if not args.username:
            parser.error("-u/--username is required for a live scan")
        if not (args.password or args.nthash or args.kerberos or args.aes_key):
            parser.error("one of -p/--password, --nthash, --kerberos, or --aes-key is required")

    banner()

    run_id, run_dir = loot.new_run_dir(_ROOT)
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    console.print(f"[*] Run:      {run_id}")
    console.print(f"[*] Loot dir: {run_dir}\n")

    if args.bloodhound:
        mode = "bloodhound-import"
        store = _run_bloodhound_import(args, run_id, run_dir)
        dashboard = None
    else:
        mode = "live"
        dashboard, store = _run_live(args, run_id, run_dir)
        console.print()
        dashboard.print_summary(run_id, run_dir, store)

    loot.save_store(run_dir, store)
    meta = {
        "run_id": run_id,
        "mode": mode,
        "started_at": started_at,
        "ended_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "target": args.bloodhound if args.bloodhound else args.dc,
        "domain": store.domain or "",
        "domain_sid": store.domain_sid or "",
        "username": args.username or "",
        "object_count": len(store),
        "principal_count": len(store.principals()),
        "session_count": len(store.sessions),
        "gpo": (mode == "live" and not args.no_gpo),
        "host_rights": args.hosts or ("all" if args.host_rights else ""),
        "live_sessions": args.session_hosts or ("all" if args.sessions else ""),
        "adcs_ca_config": bool(args.adcs_ca_config),
    }
    loot.save_meta(run_dir, meta)
    console.print(f"\n[bold green]Loot saved:[/] {run_dir}")
    console.print(f"[dim]Next: python3 adcontrol_web.py --run {run_id}[/]")


if __name__ == "__main__":
    main()
