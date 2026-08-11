#!/usr/bin/env python3
"""
adcontrol Web — read-only viewer/reporter for runs produced by adcontrol_scan.py.

This process never gathers/scans anything itself. It works purely off the
on-disk loot/<run_id>/ folders that adcontrol_scan.py writes, and lets you pick
which run's data to view (from the CLI or the in-browser picker). While serving,
it shows a fixed-size terminal dashboard (rich) with the loaded run and recent
requests, instead of Flask's default endlessly-scrolling access log.

Usage:
  # Start with nothing loaded — pick a run from the browser
  python3 adcontrol_web.py

  # Load the most recently finished run on startup
  python3 adcontrol_web.py --latest

  # Load a specific run on startup
  python3 adcontrol_web.py --run 20260811_120000
"""

import argparse
import logging
import os
import sys
import threading
import time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

_ROOT = os.path.dirname(os.path.abspath(__file__))

console = Console()


def banner():
    console.print(r"""
[bold cyan]           _                _             _
  __ _  __| | ___ ___  _ __ | |_ _ __ ___ | |
 / _` |/ _` |/ __/ _ \| '_ \| __| '__/ _ \| |
| (_| | (_| | (_| (_) | | | | |_| | | (_) | |
 \__,_|\__,_|\___\___/|_| |_|\__|_|  \___/|_|[/]
[dim]        Web viewer — read-only, no scanning capability[/]
""")


def _resolve_run_id(args):
    from adcontrol import loot
    if args.run:
        return args.run
    if args.latest:
        latest = loot.latest_run(_ROOT)
        if latest is None:
            sys.exit("[!] no loot runs found in loot/")
        return latest["run_id"]
    return None


def _no_gui_report(args):
    """--subject / --offline-report: generate a report from a loaded run and
    exit, without starting the web server."""
    run_id = _resolve_run_id(args)
    if not run_id:
        sys.exit("--subject/--offline-report requires --run <id> or --latest")

    from adcontrol.app import load_run_for_cli
    print(f"[*] Loading run: {run_id}")
    try:
        store, az = load_run_for_cli(run_id)
    except ValueError as e:
        sys.exit(str(e))
    print(f"[*] {len(store)} objects / {len(store.principals())} principals loaded")

    if args.offline_report is not None:
        import time as _time
        from adcontrol import report_domain
        if args.offline_report:
            path = args.offline_report
        else:
            safe_domain = (store.domain or "domain").replace(" ", "_")
            stamp = _time.strftime("%Y%m%d_%H%M%S")
            path = f"adcontrol_{safe_domain}_{stamp}.html"
        print("[*] building domain-wide report (summary + queries + Tier-0 paths "
              "+ per-principal control)…")
        t0 = _time.time()
        body = report_domain.to_html(store)
        with open(path, "w") as fh:
            fh.write(body)
        print(f"[*] report written: {path}  ({len(body)/1_000_000:.1f} MB, {_time.time()-t0:.1f}s)")
        return

    matches = [m for m in store.find(args.subject)
               if m.object_class in ("user", "group", "computer")]
    if not matches:
        sys.exit(f"no principal matching '{args.subject}'")
    subj = matches[0]
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

    if args.report:
        from adcontrol import report as report_mod
        fmt = "md" if args.report.lower().endswith(".md") else "html"
        body = (report_mod.to_markdown if fmt == "md" else report_mod.to_html)(store, subj, az)
        with open(args.report, "w") as fh:
            fh.write(body)
        print(f"\nReport written: {args.report}")


# ── fixed-box terminal dashboard for the serving path ───────────────────────
# Flask's dev server logs every request straight to stdout/stderr forever;
# here we intercept both the werkzeug access log (via a logging.Handler) and
# any stray prints (its startup banner/warning) and render them inside a
# bounded rich.Live box instead, the same style as adcontrol_scan.py.

import re

_RE_REQUEST = re.compile(r'"(\S+)\s+(\S+)\s+HTTP/[\d.]+"\s+(\d{3})')


class WebDashboard:
    def __init__(self, header_lines, host, port):
        self.header_lines = header_lines
        self.host = host
        self.port = port
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.activity = deque(maxlen=14)
        self.request_count = 0
        self.status_counts = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}

    def add_request(self, line: str):
        m = _RE_REQUEST.search(line)
        with self.lock:
            self.request_count += 1
            if m:
                method, path, status = m.group(1), m.group(2), m.group(3)
                bucket = f"{status[0]}xx" if status[0] in "2345" else "other"
                self.status_counts[bucket] = self.status_counts.get(bucket, 0) + 1
                self.activity.appendleft(("req", status, method, path))
            else:
                self.activity.appendleft(("note", "", "", line))

    def add_note(self, line: str, level: str = "info"):
        if not line.strip():
            return
        with self.lock:
            self.activity.appendleft(("note", level, "", line.strip()))

    def render(self):
        from adcontrol.app import STATE

        elapsed = int(time.time() - self.start_time)
        with self.lock:
            activity = list(self.activity)
            counts = dict(self.status_counts)
            total = self.request_count

        header = Text()
        for i, line in enumerate(self.header_lines):
            if i:
                header.append("\n")
            header.append(line)

        store = STATE.get("store")
        run_panel_lines = Text()
        if store is not None:
            run_panel_lines.append(f"Run:        {STATE.get('run_id')}\n", style="bold green")
            run_panel_lines.append(f"Domain:     {store.domain or '?'}\n")
            run_panel_lines.append(f"Objects:    {len(store)}\n")
            run_panel_lines.append(f"Principals: {len(store.principals())}")
        else:
            run_panel_lines.append("No run loaded — pick one in the browser.", style="dim")

        stats = Table.grid(padding=(0, 2))
        stats.add_row(Text("Requests", style="cyan"), Text(str(total), style="bold cyan"))
        for bucket, style in (("2xx", "green"), ("3xx", "yellow"), ("4xx", "red"), ("5xx", "red")):
            if counts.get(bucket):
                stats.add_row(Text(bucket, style=style), Text(str(counts[bucket]), style=style))
        stats.add_row(Text("Uptime", style="dim"), Text(str(elapsed) + "s", style="dim"))

        top = Table.grid(expand=True)
        top.add_column(ratio=1)
        top.add_column(ratio=1)
        top.add_row(
            Panel(run_panel_lines, title="Loaded run", border_style="magenta"),
            Panel(stats, title="Server stats", border_style="cyan"),
        )

        act_tbl = Table(show_header=False, expand=True, box=None)
        act_tbl.add_column("activity", overflow="fold")
        status_style = {"2": "green", "3": "yellow", "4": "red", "5": "bold red"}
        for kind, a, b, c in activity:
            if kind == "req":
                status = a
                style = status_style.get(status[0], "")
                act_tbl.add_row(Text(f"{b:<6} {c:<45} ", style="") + Text(status, style=style))
            else:
                level = a
                color = {"warn": "yellow", "error": "red"}.get(level, "dim")
                act_tbl.add_row(Text(c, style=color))
        if not activity:
            act_tbl.add_row(Text("(waiting for requests...)", style="dim"))

        pieces = [
            Panel(header, title="adcontrol Web", border_style="blue"),
            top,
            Panel(act_tbl, title="Recent activity", border_style="green"),
        ]
        return Group(*pieces)


class _DashboardLogHandler(logging.Handler):
    """Routes werkzeug's per-request access log into the dashboard instead of
    stdout, so it renders inside the fixed box instead of scrolling forever."""

    def __init__(self, dashboard: WebDashboard):
        super().__init__()
        self.dashboard = dashboard

    def emit(self, record):
        try:
            self.dashboard.add_request(record.getMessage())
        except Exception:
            pass


class _CapturingStream:
    """Replaces sys.stdout/stderr while the Flask dev server runs, so its
    startup banner ('* Serving Flask app...', the dev-server warning, etc.) —
    which prints directly rather than through logging — lands in the
    dashboard's activity box instead of the raw terminal."""

    def __init__(self, dashboard: WebDashboard, level: str):
        self.dashboard = dashboard
        self.level = level
        self._buf = ""

    def write(self, s):
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self.dashboard.add_note(line, self.level)
        return len(s)

    def flush(self):
        pass


def _serve_with_dashboard(host, port, initial_run):
    from adcontrol.app import run as run_gui

    header_lines = [
        f"GUI:  http://{host}:{port}",
        f"Mode: read-only viewer (no scanning capability)",
    ]
    dashboard = WebDashboard(header_lines, host, port)

    werkzeug_logger = logging.getLogger("werkzeug")
    werkzeug_logger.setLevel(logging.INFO)
    werkzeug_logger.handlers = [_DashboardLogHandler(dashboard)]
    werkzeug_logger.propagate = False

    def worker():
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = _CapturingStream(dashboard, "info")
        sys.stderr = _CapturingStream(dashboard, "warn")
        try:
            run_gui(host=host, port=port, initial_run=initial_run)
        except Exception as e:
            dashboard.add_note(f"[fatal] web server error: {e}", "error")
        finally:
            sys.stdout, sys.stderr = old_out, old_err

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    time.sleep(0.3)  # let the initial run-load (if any) land before first render

    try:
        with Live(dashboard.render(), console=console, refresh_per_second=4, screen=False) as live:
            while t.is_alive():
                live.update(dashboard.render())
                time.sleep(0.25)
            live.update(dashboard.render())
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down.[/]")


def main():
    parser = argparse.ArgumentParser(
        description="adcontrol Web — read-only viewer/reporter for adcontrol_scan.py loot runs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=5006, help="Web GUI port")

    run_group = parser.add_mutually_exclusive_group()
    run_group.add_argument("--run", metavar="RUN_ID", help="Load a specific run")
    run_group.add_argument("--latest", action="store_true", help="Load the most recent run")

    parser.add_argument("--subject", metavar="NAME",
                         help="No-GUI: print outbound/inbound for this principal from "
                              "--run/--latest, then exit (requires --run or --latest)")
    parser.add_argument("--report", metavar="PATH",
                         help="With --subject: also write a scoped report (.html or .md)")
    parser.add_argument("--offline-report", metavar="PATH", nargs="?", const="",
                         help="No-GUI: write one self-contained whole-domain HTML report "
                              "(canned queries + Tier-0 paths + every principal's control) "
                              "from --run/--latest, then exit. Path defaults to "
                              "adcontrol_<DOMAIN>_<timestamp>.html if omitted.")

    args = parser.parse_args()

    if args.subject or args.offline_report is not None:
        _no_gui_report(args)
        return

    banner()

    initial_run = _resolve_run_id(args)
    if initial_run:
        console.print(f"[*] Loading run: {initial_run}")
    else:
        console.print("[*] No run specified — pick one from the browser.")
    console.print(f"[*] Web GUI: http://{args.host}:{args.port}\n")

    _serve_with_dashboard(args.host, args.port, initial_run)


if __name__ == "__main__":
    main()
