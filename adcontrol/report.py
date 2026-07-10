"""
Scoped report export for a single principal/object.

Renders the outbound + inbound control analysis (kept in separate sections) as
either Markdown or a self-contained HTML file. Optional extra planes (GPO,
per-host RDP/logon) are appended when supplied.
"""

from __future__ import annotations

import html
import datetime

from adcontrol.model import RawObject
from adcontrol.analyze import Analyzer

_SEV_COLOR = {"high": "#e5484d", "medium": "#e0a800", "low": "#3a9e6a"}


def _edge_rows_md(edges, direction):
    if not edges:
        return "_None._\n"
    lines = ["| Severity | Right | " + ("Target" if direction == "out" else "Principal")
             + " | Class | Via | Scope |",
             "|---|---|---|---|---|---|"]
    for e in edges:
        who = e.target_label if direction == "out" else e.source_label
        scope = e.applies_to or "whole object"
        lines.append(f"| {e.severity} | {e.right} | {who} | {e.target_class} | {e.via} | {scope} |")
    return "\n".join(lines) + "\n"


def _policy_rows_md(policy_rights):
    if not policy_rights:
        return "_None found (or GPO/host planes not collected)._\n"
    lines = ["| Plane | Severity | Right | Applies to | Source |",
             "|---|---|---|---|---|"]
    for pr in policy_rights:
        lines.append(f"| {pr.plane} | {pr.severity} | {pr.right} | {pr.applies_to} | {pr.source} |")
    return "\n".join(lines) + "\n"


def to_markdown(store, subject: RawObject, analyzer: Analyzer | None = None) -> str:
    analyzer = analyzer or Analyzer(store)
    s = analyzer.summarize(subject)
    subj = s["subject"]
    now = datetime.datetime.now().isoformat(timespec="seconds")
    out = []
    out.append(f"# Control report — {subj['label']}\n")
    out.append(f"_Generated {now} from {store.source} · domain `{store.domain}`_\n")
    out.append("## Identity\n")
    out.append(f"- **DN:** `{subj['dn']}`")
    out.append(f"- **SID:** `{subj['sid']}`")
    out.append(f"- **Class:** {subj['class']}  ·  **Enabled:** {subj['enabled']}  "
               f"·  **adminCount:** {subj['admin_count']}")
    out.append(f"- **Transitive group memberships:** {s['effective_group_count']}")
    if subj["spn"]:
        out.append(f"- **SPNs (kerberoastable):** {', '.join(subj['spn'])}")
    out.append("")
    out.append(f"## Outbound control — what {subj['label']} can control  "
               f"({len(s['outbound'])} edges, {s['outbound_high']} high)\n")
    out.append(_edge_rows_md(s["outbound"], "out"))
    out.append(f"\n## Inbound control — who can control {subj['label']}  "
               f"({len(s['inbound'])} edges, {s['inbound_high']} high)\n")
    out.append(_edge_rows_md(s["inbound"], "in"))
    out.append(f"\n## GPO-delivered & per-host RDP / logon rights  "
               f"({len(s['policy_rights'])})\n")
    out.append("_Rights this principal (or a group it belongs to) gains from "
               "Group Policy or local host membership — RDP, local admin, logon "
               "rights. Separate from the AD-object control graph above._\n")
    out.append(_policy_rows_md(s["policy_rights"]))
    return "\n".join(out) + "\n"


def _edge_rows_html(edges, direction):
    if not edges:
        return '<p class="none">None.</p>'
    head = "Target" if direction == "out" else "Principal"
    rows = []
    for e in edges:
        who = html.escape(e.target_label if direction == "out" else e.source_label)
        scope = html.escape(e.applies_to or "whole object")
        color = _SEV_COLOR.get(e.severity, "#888")
        badge = ' <span class="broad">BROAD</span>' if e.broad else ""
        rows.append(
            f'<tr><td><span class="sev" style="background:{color}">{e.severity}</span></td>'
            f'<td class="right">{html.escape(e.right)}</td>'
            f'<td>{who}{badge}</td><td>{html.escape(e.target_class)}</td>'
            f'<td>{html.escape(e.via)}</td><td class="scope">{scope}</td></tr>'
        )
    return (f'<table><thead><tr><th>Severity</th><th>Right</th><th>{head}</th>'
            f'<th>Class</th><th>Via</th><th>Scope</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>')


def _policy_rows_html(policy_rights):
    if not policy_rights:
        return '<p class="none">None found (or GPO/host planes not collected).</p>'
    rows = []
    for pr in policy_rights:
        color = _SEV_COLOR.get(pr.severity, "#888")
        trustees = html.escape(", ".join(str(t) for t in pr.trustees))
        rows.append(
            f'<tr><td><span class="pill">{html.escape(pr.plane)}</span></td>'
            f'<td><span class="sev" style="background:{color}">{pr.severity}</span></td>'
            f'<td class="right">{html.escape(pr.right)}</td>'
            f'<td>{trustees}</td>'
            f'<td class="scope">{html.escape(pr.applies_to)}</td>'
            f'<td class="scope">{html.escape(pr.source)}</td></tr>')
    return ('<table><thead><tr><th>Plane</th><th>Severity</th><th>Right</th>'
            '<th>Granted to</th><th>Applies to</th><th>Source</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>')


def to_html(store, subject: RawObject, analyzer: Analyzer | None = None) -> str:
    analyzer = analyzer or Analyzer(store)
    s = analyzer.summarize(subject)
    subj = s["subject"]
    now = datetime.datetime.now().isoformat(timespec="seconds")
    spn = ("<p><b>SPNs (kerberoastable):</b> " + html.escape(", ".join(subj["spn"])) + "</p>") if subj["spn"] else ""
    extra = ('<h2>GPO-delivered &amp; per-host RDP / logon rights</h2>'
             '<p class="meta">Rights this principal (or a group it belongs to) '
             'gains from Group Policy or local host membership — separate from '
             'the AD-object control graph.</p>'
             '<div class="tableWrap">' + _policy_rows_html(s["policy_rights"]) + '</div>')

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Control report — {html.escape(subj['label'])}</title>
<style>
:root{{color-scheme:light dark}}
body{{font:15px/1.5 system-ui,sans-serif;margin:0;padding:2rem;max-width:1100px;
  margin-inline:auto;background:#fbfbfc;color:#1a1a1a}}
@media(prefers-color-scheme:dark){{body{{background:#151517;color:#e7e7ea}}
  table{{background:#1d1d20}} th{{background:#26262b}} code,.mono{{background:#26262b}}}}
h1{{font-size:1.6rem;margin:0 0 .2rem}} h2{{font-size:1.15rem;margin:1.8rem 0 .5rem;
  border-bottom:1px solid #8884;padding-bottom:.3rem}}
.meta{{color:#888;font-size:.85rem;margin-bottom:1rem}}
.pill{{font-size:.68rem;text-transform:uppercase;padding:.1em .5em;border-radius:99px;background:#8883;color:#666}}
code,.mono{{background:#eee;padding:.1em .35em;border-radius:4px;font-size:.85em}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
  overflow:hidden;box-shadow:0 1px 3px #0002;font-size:.9rem;margin:.5rem 0}}
th,td{{text-align:left;padding:.5rem .7rem;border-bottom:1px solid #8882;vertical-align:top}}
th{{background:#f3f3f5;font-weight:600}}
.sev{{color:#fff;padding:.1em .5em;border-radius:99px;font-size:.75rem;text-transform:uppercase}}
.right{{font-weight:600}} .scope{{color:#888;font-size:.85em}}
.broad{{background:#e5484d;color:#fff;font-size:.65rem;padding:.05em .4em;border-radius:4px;
  vertical-align:middle;margin-left:.3em}}
.none{{color:#888;font-style:italic}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}}
.card{{background:#fff;border-radius:8px;padding:.8rem 1.1rem;box-shadow:0 1px 3px #0002;min-width:120px}}
@media(prefers-color-scheme:dark){{.card{{background:#1d1d20}}}}
.card b{{display:block;font-size:1.7rem;line-height:1}}
.tableWrap{{overflow-x:auto}}
</style></head><body>
<h1>Control report — {html.escape(subj['label'])}</h1>
<div class="meta">Generated {now} · source {html.escape(store.source)} · domain <code>{html.escape(store.domain)}</code></div>
<div class="cards">
  <div class="card"><b>{len(s['outbound'])}</b>outbound edges</div>
  <div class="card"><b style="color:#e5484d">{s['outbound_high']}</b>outbound high</div>
  <div class="card"><b>{len(s['inbound'])}</b>inbound edges</div>
  <div class="card"><b style="color:#e5484d">{s['inbound_high']}</b>inbound high</div>
  <div class="card"><b>{s['effective_group_count']}</b>groups</div>
</div>
<h2>Identity</h2>
<p><b>DN:</b> <code>{html.escape(subj['dn'])}</code><br>
<b>SID:</b> <code>{html.escape(subj['sid'])}</code><br>
<b>Class:</b> {html.escape(subj['class'])} · <b>Enabled:</b> {subj['enabled']} · <b>adminCount:</b> {subj['admin_count']}</p>
{spn}
<h2>Outbound control — what {html.escape(subj['label'])} can control</h2>
<div class="tableWrap">{_edge_rows_html(s['outbound'], 'out')}</div>
<h2>Inbound control — who can control {html.escape(subj['label'])}</h2>
<div class="tableWrap">{_edge_rows_html(s['inbound'], 'in')}</div>
{extra}
</body></html>"""
