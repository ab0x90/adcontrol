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
from adcontrol.paths import PathFinder

_SEV_COLOR = {"high": "#e5484d", "medium": "#e0a800", "low": "#3a9e6a"}


def _compute_paths(store, subject, analyzer):
    """Shortest attack paths from the subject to the Tier-0 goal set. Returns
    (already_tier0, [AttackPath]). Reports use short mode — a report is a
    summary, not an exhaustive enumeration."""
    pf = PathFinder(analyzer)
    if pf.already_tier0(subject):
        return True, []
    return False, pf.find(subject, mode="short")


def _path_chain_text(path):
    """One-line 'a --Right--> b --Right--> c' rendering of a path."""
    if not path.hops:
        return ""
    parts = [path.hops[0].source_label]
    for h in path.hops:
        parts.append(f"--[{h.right}]-->")
        parts.append(h.target_label)
    return " ".join(parts)


def _session_rows(store, subject):
    """(other_label, kind, role) for each logon session relevant to the subject:
    a computer's logged-on users, or a user's hosts. Empty for other classes."""
    rows = []
    if subject.object_class == "computer" and subject.sid:
        for sess in store.sessions_on_host(subject.sid):
            u = store.by_sid(sess.user_sid)
            rows.append(((u.label if u else sess.user_sid), sess.kind, "user on host"))
    elif subject.object_class == "user" and subject.sid:
        for sess in store.sessions_of_user(subject.sid):
            c = store.by_sid(sess.computer_sid)
            rows.append(((c.label if c else sess.computer_sid), sess.kind, "host"))
    order = {"privileged": 0, "registry": 1, "netsession": 2}
    rows.sort(key=lambda r: (order.get(r[1], 9), r[0].lower()))
    return rows


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
    if subj.get("gmsa"):
        out.append("- **gMSA** (password retrievable via msDS-GroupMSAMembership)")
    if subj.get("flags"):
        out.append(f"- **Account flags:** {', '.join(subj['flags'])}")
    out.append("")
    out.append(f"## Outbound control — what {subj['label']} can control  "
               f"({len(s['outbound'])} edges, {s['outbound_high']} high)\n")
    out.append(_edge_rows_md(s["outbound"], "out"))
    already, paths = _compute_paths(store, subject, analyzer)
    out.append(f"\n## Attack paths to Tier-0  ({len(paths)})\n")
    out.append("_Multi-hop control chains from this principal to Domain/Enterprise "
               "Admins or the domain root. Each hop is a control edge pivoted "
               "through (controlling a principal lets you act as it). Shortest "
               "path per target._\n")
    if already:
        out.append("_This principal is already Tier-0 (effectively Domain/Enterprise "
                   "Admin), so there is no path to *reach* Tier-0._\n")
    elif not paths:
        out.append("_No control path to Tier-0 found from this principal._\n")
    else:
        for p in paths:
            out.append(f"- **{p.length} hop{'' if p.length == 1 else 's'} → {p.win}:** "
                       f"{_path_chain_text(p)}")
        out.append("")
    out.append(f"\n## Inbound control — who can control {subj['label']}  "
               f"({len(s['inbound'])} edges, {s['inbound_high']} high)\n")
    out.append(_edge_rows_md(s["inbound"], "in"))
    sess = _session_rows(store, subject)
    if subject.object_class in ("user", "computer"):
        out.append(f"\n## Logon sessions  ({len(sess)})\n")
        out.append("_" + ("Users logged on to this host" if subject.object_class == "computer"
                          else "Hosts this user is logged on to")
                   + " at collection time. Privileged/registry sessions are reliable "
                     "credential-theft opportunities; net-sessions can be stale._\n")
        if sess:
            lines = ["| Confidence | " + ("User" if subject.object_class == "computer" else "Host") + " |",
                     "|---|---|"]
            for label, kind, _role in sess:
                lines.append(f"| {kind} | {label} |")
            out.append("\n".join(lines) + "\n")
        else:
            out.append("_No sessions collected._\n")
    reach = s["local_admin_rdp"]
    if subject.object_class in ("user", "computer") and (reach["local_admin"] or reach["rdp"]):
        out.append(f"\n## 🔑 Local Admin access  ({len(reach['local_admin'])})\n")
        out.append("_Systems where this principal — directly or through a group — is a "
                   "member of local Administrators. **Via** = direct or which group._\n")
        out.append(_reach_rows_md(reach["local_admin"], "Local admin"))
        out.append(f"\n## 🖥 RDP access  ({len(reach['rdp'])})\n")
        out.append("_Systems this principal can log on to via RDP (Remote Desktop Users "
                   "or SeRemoteInteractiveLogonRight)._\n")
        out.append(_reach_rows_md(reach["rdp"], "RDP access"))
    if s.get("adcs"):
        out.append(f"\n## 🎗 ADCS certificate abuse (ESC)  ({len(s['adcs'])})\n")
        out.append("_Vulnerable certificate templates this principal (or a group it "
                   "belongs to) can enroll or control._\n")
        out.append("| ESC | Template | Why it works | Conditions |")
        out.append("|---|---|---|---|")
        for f in s["adcs"]:
            out.append(f"| {f['esc']} | {f['template']} | {f['detail']} | "
                       f"{', '.join(f.get('reasons', []))} |")
        out.append("")
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


def _sessions_html(store, subject):
    sess = _session_rows(store, subject)
    head = "User" if subject.object_class == "computer" else "Host"
    if not sess:
        return '<p class="none">No logon sessions collected.</p>'
    rows = []
    for label, kind, _role in sess:
        cls = "broad" if kind == "privileged" else "pill"
        rows.append(f'<tr><td><span class="{cls}">{html.escape(kind)}</span></td>'
                    f'<td>{html.escape(label)}</td></tr>')
    return (f'<table><thead><tr><th>Confidence</th><th>{head}</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>')


def _sessions_section_html(store, subject):
    """Full <h2> sessions section, or empty for non-principal subjects."""
    if subject.object_class not in ("user", "computer"):
        return ""
    lead = ("Users logged on to this host" if subject.object_class == "computer"
            else "Hosts this user is logged on to")
    return ('<h2>Logon sessions</h2>'
            f'<p class="meta">{lead} at collection time. Privileged/registry '
            'sessions are reliable credential-theft opportunities; net-sessions '
            'can be stale.</p>'
            '<div class="tableWrap">' + _sessions_html(store, subject) + '</div>')


def _paths_html(already, paths):
    if already:
        return ('<p class="none">This principal is already Tier-0 (effectively '
                'Domain/Enterprise Admin), so there is no path to <i>reach</i> Tier-0.</p>')
    if not paths:
        return '<p class="none">No control path to Tier-0 found from this principal.</p>'
    cards = []
    for p in paths:
        chain = []
        if p.hops:
            chain.append(f'<span class="pnode">{html.escape(p.hops[0].source_label)}</span>')
            for h in p.hops:
                right = html.escape(h.right)
                color = _SEV_COLOR.get(h.severity, "#888")
                chain.append(f'<span class="parrow">→ <span class="prt" '
                             f'style="color:{color}">{right}</span> →</span>')
                chain.append(f'<span class="pnode">{html.escape(h.target_label)}</span>')
        hops = p.length
        cards.append(
            f'<div class="pathcard"><div class="pathmeta">'
            f'<span class="pill">{hops} hop{"" if hops == 1 else "s"}</span> '
            f'<span class="winbadge">WIN → {html.escape(p.win)}</span></div>'
            f'<div class="pathchain">{"".join(chain)}</div></div>')
    return "".join(cards)


def _reach_rows_html(rows, host_head):
    if not rows:
        return f'<p class="none">None — subject has no {host_head.lower()} to any collected host.</p>'
    body = []
    for r in rows:
        via = html.escape(r["via"])
        via_cls = "reachdirect" if r["via"] == "direct" else "pill"
        color = _SEV_COLOR.get(r["severity"], "#888")
        body.append(
            f'<tr><td class="right">{html.escape(r["host"])}</td>'
            f'<td><span class="{via_cls}">{via}</span></td>'
            f'<td><span class="sev" style="background:{color}">{html.escape(r["severity"])}</span></td>'
            f'<td class="scope">{html.escape(r["right"])}</td></tr>')
    return ('<table><thead><tr><th>System</th><th>Via</th><th>Severity</th>'
            f'<th>Grant</th></tr></thead><tbody>{"".join(body)}</tbody></table>')


def _reach_section_html(subject, reach):
    """Local Admin + RDP reach tables — user/computer subjects only."""
    if subject.object_class not in ("user", "computer"):
        return ""
    la, rdp = reach["local_admin"], reach["rdp"]
    if not la and not rdp:
        return ""
    return ('<h2>🔑 Local Admin access</h2>'
            '<p class="meta">Systems where this principal — directly or through a '
            'group it belongs to — is a member of local Administrators. '
            '<b>Via</b> shows whether the access is direct or inherited from a group.</p>'
            '<div class="tableWrap">' + _reach_rows_html(la, "Local admin") + '</div>'
            '<h2>🖥 RDP access</h2>'
            '<p class="meta">Systems this principal can log on to via RDP (Remote '
            'Desktop Users membership or the SeRemoteInteractiveLogonRight user-right).</p>'
            '<div class="tableWrap">' + _reach_rows_html(rdp, "RDP access") + '</div>')


def _adcs_section_html(adcs):
    """ADCS ESC abuse section — only when the subject can abuse a vuln template."""
    if not adcs:
        return ""
    rows = []
    for f in adcs:
        color = _SEV_COLOR.get(f["severity"], "#888")
        reasons = html.escape(", ".join(f.get("reasons", [])))
        rows.append(
            f'<tr><td><span class="sev" style="background:{color}">{html.escape(f["esc"])}</span></td>'
            f'<td class="right">{html.escape(f["template"])}</td>'
            f'<td>{html.escape(f["detail"])}</td>'
            f'<td class="scope">{reasons}</td></tr>')
    return ('<h2>🎗 ADCS certificate abuse (ESC)</h2>'
            '<p class="meta">Vulnerable certificate templates this principal (or a '
            'group it belongs to) can enroll or control — a path to authentication '
            'as another identity via AD Certificate Services.</p>'
            '<div class="tableWrap"><table><thead><tr><th>ESC</th><th>Template</th>'
            '<th>Why it works</th><th>Conditions</th></tr></thead><tbody>'
            + "".join(rows) + '</tbody></table></div>')


def _reach_rows_md(rows, host_head):
    if not rows:
        return f"_None — no {host_head.lower()} to any collected host._\n"
    lines = ["| System | Via | Severity | Grant |", "|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['host']} | {r['via']} | {r['severity']} | {r['right']} |")
    return "\n".join(lines) + "\n"


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
    badges = []
    if subj.get("gmsa"):
        badges.append('<span class="pill" title="Group Managed Service Account">gMSA</span>')
    if subj.get("materialized"):
        badges.append('<span class="pill" title="Reconstructed from host-plane membership — not collected as its own AD object">reconstructed</span>')
    for fl in subj.get("flags", []):
        badges.append(f'<span class="pill">{html.escape(fl)}</span>')
    badges_html = ("<p>" + " ".join(badges) + "</p>") if badges else ""
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
.pathcard{{background:#fff;border-radius:8px;border-left:3px solid #e5484d;padding:.7rem .9rem;margin:.5rem 0;box-shadow:0 1px 3px #0002}}
@media(prefers-color-scheme:dark){{.pathcard{{background:#1d1d20}}}}
.pathmeta{{display:flex;align-items:center;gap:.6rem;margin-bottom:.5rem}}
.winbadge{{font-weight:700;color:#e5484d;font-size:.85rem}}
.pathchain{{display:flex;flex-wrap:wrap;align-items:center;gap:.25rem;line-height:2}}
.pnode{{padding:.12em .55em;border:1px solid #8884;border-radius:5px;font-weight:600;background:#8881;white-space:nowrap}}
.parrow{{color:#888;white-space:nowrap}}
.prt{{font-size:.72rem;font-weight:700}}
.reachdirect{{font-size:.68rem;text-transform:uppercase;padding:.1em .5em;border-radius:99px;
  background:#e5484d;color:#fff;font-weight:700}}
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
{badges_html}
{spn}
<h2>Outbound control — what {html.escape(subj['label'])} can control</h2>
<div class="tableWrap">{_edge_rows_html(s['outbound'], 'out')}</div>
<h2>Attack paths to Tier-0</h2>
<p class="meta">Multi-hop control chains from this principal to Domain/Enterprise
Admins or the domain root. Each hop is a control edge pivoted through —
controlling a principal lets you act as it. Shortest path per target.</p>
{_paths_html(*_compute_paths(store, subject, analyzer))}
<h2>Inbound control — who can control {html.escape(subj['label'])}</h2>
<div class="tableWrap">{_edge_rows_html(s['inbound'], 'in')}</div>
{_reach_section_html(subject, s['local_admin_rdp'])}
{_adcs_section_html(s['adcs'])}
{_sessions_section_html(store, subject)}
{extra}
</body></html>"""
