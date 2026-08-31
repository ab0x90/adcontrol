"""
Domain-wide static HTML report.

Produced by ``--offline`` (with ``--bloodhound``): a single self-contained HTML
file summarizing the whole domain, so a very large collection can be read through
without running the live web GUI (which streams over SocketIO and can lag on huge
domains). No server, no JavaScript needed to view — just open the file.

Layout:
  1. Header — domain, source, object/principal counts, collection time.
  2. Canned queries — every entry in queries.QUERY_REGISTRY with its hit rows.
  3. Attack paths to Tier-0 — shortest path per non-Tier-0 principal that has one.
  4. Per-principal control tables — outbound/inbound for every principal.

Section 4 is what makes this large; it is what the user explicitly asked for
("both in one file"). A small in-page nav lets the reader jump between sections.
"""

from __future__ import annotations

import base64
import gzip
import html
import datetime
from concurrent.futures import ThreadPoolExecutor

from adcontrol.analyze import Analyzer
from adcontrol.paths import PathFinder
from adcontrol import queries as q_mod
from adcontrol import report as report_mod   # reuse per-subject edge/session helpers

# Principal JSON above this size (bytes) is gzip-compressed + base64-encoded
# inline; the page decompresses it with the native DecompressionStream API.
_COMPRESS_THRESHOLD = 500_000

_SEV_COLOR = {"high": "#e5484d", "medium": "#e0a800", "low": "#3a9e6a"}


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _json_blob(data) -> str:
    """JSON for embedding in a <script type="application/json"> tag. Escapes '<'
    so a value containing '</script>' can't break out of the tag."""
    import json
    return json.dumps(data, separators=(",", ":")).replace("<", "\\u003c")


def _query_section(qid, label, desc, hits) -> str:
    # Actor-grouped shape: rows carry a nested item list ("takeovers" or "gpos").
    item_key = "takeovers" if any("takeovers" in h for h in hits) else (
        "gpos" if any("gpos" in h for h in hits) else None)
    if not hits:
        body = '<p class="none">No hits.</p>'
    elif item_key:
        # One expandable block per actor, listing the objects/GPOs it controls.
        # Expected built-in privileged groups are hidden by default (rights by
        # design) with a toggle to reveal them.
        n_expected = sum(1 for h in hits if h.get("expected"))
        noun = "object" if item_key == "takeovers" else "GPO"
        toggle = (f'<label class="qtoggle"><input type="checkbox" '
                  f'onchange="toggleExpected(\'{_esc(qid)}\',this.checked)"> '
                  f'Show {n_expected} expected built-in privileged group'
                  f'{"" if n_expected == 1 else "s"} '
                  f'(admins, operators — control by design)</label>'
                  ) if n_expected else ""
        blocks = "".join(_actor_block(h, item_key) for h in hits)
        empty = (f'<p class="none" data-empty="1" hidden>Only expected built-in '
                 f'privileged groups control {noun}s here — enable the toggle to '
                 f'see them.</p>') if n_expected == len(hits) else ""
        body = f'{toggle}<div class="qbody">{blocks}{empty}</div>'
    else:
        rows = []
        for r in hits:
            note = _esc(r.get("note", ""))
            mc = r.get("member_count")
            memnote = f' · {mc} member(s)' if mc is not None else ""
            rows.append(
                f'<tr><td><span class="pill {_esc(r.get("class",""))}">{_esc(r.get("class",""))}</span></td>'
                f'<td class="rt">{_esc(r.get("label",""))}</td>'
                f'<td class="scope">{note}{memnote}</td></tr>')
        body = ('<table><thead><tr><th>Class</th><th>Principal</th><th>Why</th>'
                f'</tr></thead><tbody>{"".join(rows)}</tbody></table>')
    # Count badge reflects what's visible by default: for actor-grouped takeover
    # rows the expected built-ins are hidden, so show the non-expected count.
    default_count = sum(1 for h in hits if not h.get("expected"))
    return (f'<section id="q_{_esc(qid)}"><h3>{_esc(label)} '
            f'<span class="count">{default_count}</span></h3>'
            f'<p class="meta">{_esc(desc)}</p>{body}</section>')


def _actor_block(h, item_key) -> str:
    """One expandable block per actor, revealing the objects/GPOs it controls.
    ``item_key`` is "takeovers" (objects, with a direct/broad How column) or
    "gpos" (GPOs, no How column)."""
    items = h.get(item_key, [])
    n = len(items)
    is_takeover = item_key == "takeovers"
    noun = "object" if is_takeover else "GPO"
    obj_head = "Object" if is_takeover else "GPO"

    def kind_badge(k):
        if k == "direct":
            return ('<span class="pill tk-direct" title="Direct takeover primitive '
                    '(shadow creds / RBCD / write-SPN)">direct</span>')
        return ('<span class="pill tk-broad" title="Broad full-control right '
                '(GenericAll/Write, WriteDacl/Owner, AllExtendedRights) that '
                'encompasses the takeover primitives">via full control</span>')

    rows = ""
    for t in items:
        how = f'<td>{kind_badge(t.get("kind","broad"))}</td>' if is_takeover else ""
        tclass = (f'<td><span class="pill {_esc(t.get("target_class",""))}">'
                  f'{_esc(t.get("target_class",""))}</span></td>') if is_takeover else ""
        rows += (f'<tr>{tclass}<td class="rt">{_esc(t["target"])}</td>'
                 f'{how}<td class="scope">{_esc(t["right"])}</td></tr>')
    class_head = "<th>Class</th>" if is_takeover else ""
    how_head = "<th>How</th>" if is_takeover else ""
    table = (f'<table><thead><tr>{class_head}<th>{obj_head}</th>{how_head}'
             '<th>Via right</th>'
             f'</tr></thead><tbody>{rows}</tbody></table>')
    expected = h.get("expected")
    cls = "prin expected" if expected else "prin"
    hidden = " hidden" if expected else ""
    ebadge = ('<span class="pill" title="Built-in AD group — these rights are '
              'expected by design">expected</span> ') if expected else ""
    return (f'<details class="{cls}"{hidden}><summary>'
            f'<span class="pill {_esc(h.get("class",""))}">{_esc(h.get("class",""))}</span> '
            f'{ebadge}{_esc(h.get("label",""))} '
            f'<span class="count">{n} {noun}{"" if n == 1 else "s"}</span>'
            f'</summary>{table}</details>')


def _path_cells(p) -> str:
    """The <td> cells for a path row (length, reaches, chain) — no <tr>, so the
    caller can prepend a principal-name cell."""
    chain = _esc(p.hops[0].source_label) if p.hops else ""
    for h in p.hops:
        chain += (f' <span class="arw">--[{_esc(h.right)}]--&gt;</span> '
                  f'{_esc(h.target_label)}')
    return (f'<td><span class="pill">{p.length} hop{"" if p.length==1 else "s"}</span></td>'
            f'<td class="win">{_esc(p.win)}</td><td class="chain">{chain}</td>')


def _paths_section(store, az) -> str:
    pf = PathFinder(az)
    principals = [o for o in store.objects.values()
                  if o.object_class in ("user", "group", "computer")]

    # Pre-compute the SID key sets so we can reject principals with no pivot
    # edges in O(effective_sids) rather than launching a full BFS. On a domain
    # with hundreds of thousands of users this eliminates > 99 % of BFS calls.
    acl_sids = set(az.acl_index.keys())
    hai_sids  = set(az.host_admin_index.keys())

    def _has_any_pivot(obj):
        for sid in az.graph.effective_sids(obj):
            if sid in acl_sids or sid in hai_sids:
                return True
        return False

    rows = []
    n_reach = 0
    for subj in principals:
        if pf.already_tier0(subj):
            continue
        if not _has_any_pivot(subj):
            continue
        paths = pf.find(subj, mode="short")
        if not paths:
            continue
        n_reach += 1
        best = paths[0]   # shortest, already sorted
        rows.append((subj.label, best))
    rows.sort(key=lambda x: (x[1].length, x[0].lower()))
    if not rows:
        body = '<p class="none">No non-Tier-0 principal has a control path to Tier-0.</p>'
    else:
        trs = []
        for label, best in rows:
            trs.append(f'<tr><td class="rt">{_esc(label)}</td>{_path_cells(best)}</tr>')
        body = ('<table><thead><tr><th>Principal</th><th>Length</th><th>Reaches</th>'
                f'<th>Shortest path</th></tr></thead><tbody>{"".join(trs)}</tbody></table>')
    return (f'<section id="paths"><h3>Attack paths to Tier-0 '
            f'<span class="count">{n_reach}</span></h3>'
            '<p class="meta">Shortest control chain from each non-Tier-0 principal '
            'to Domain/Enterprise Admins, the domain root, or a Domain Controller. '
            'Each hop is a control edge pivoted through.</p>'
            f'{body}</section>')


def _edge_data(e, direction) -> dict:
    """Compact JSON for one control edge — the fields the client renders."""
    return {"s": e.severity[0],   # h/m/l — 1 char to keep the blob small
            "r": e.right,
            "w": (e.target_label if direction == "out" else e.source_label),
            "c": e.target_class if direction == "out" else "",
            "v": e.via,
            "b": 1 if e.broad else 0,
            "n": 1 if e.builtin_noise else 0}


def _principal_data(store, az, subj) -> dict:
    """The lazy-render payload for one principal: a light summary plus its edge
    lists, keyed by an index. The DOM only gets the summary row up front; the
    edges are rendered on demand when the row is expanded (see the report JS)."""
    s = az.summarize(subj)
    sess = []
    for row in report_mod._session_rows(store, subj) if hasattr(report_mod, "_session_rows") else []:
        sess.append({"label": row[0], "kind": row[1]})
    # Friendly class for display/search — collapse the verbose GPO class name.
    friendly = "gpo" if subj.object_class in ("groupPolicyContainer", "gpo") else subj.object_class
    return {
        "label": subj.label,
        "class": friendly,
        "dn": subj.dn,
        "oh": s["outbound_high"], "ih": s["inbound_high"],
        "out": [_edge_data(e, "out") for e in s["outbound"]],
        "in": [_edge_data(e, "in") for e in s["inbound"]],
        "sess": sess,
        # lowercased search haystack (friendly class so "gpo" matches)
        "q": f"{subj.label} {friendly} {subj.dn}".lower(),
    }


# Lazy rendering (below) keeps the DOM tiny regardless of domain size, so we no
# longer need to cap the number of principals — every one with a control edge is
# included. (Kept as a param for callers/back-compat; None = unbounded.)
_PRINCIPAL_CAP = None


def to_html(store, *, include_principals=True, principal_cap=_PRINCIPAL_CAP) -> str:
    """Whole-domain HTML report string.

    ``include_principals`` toggles the per-principal control section (the large
    part). ``principal_cap`` bounds how many principals get a detail block; None
    means unbounded (--full). Only principals that HAVE a control edge are
    included — leaf objects with no inbound/outbound control add size but no
    signal, so they are omitted regardless."""
    az = Analyzer(store)
    _ = az.acl_index        # warm before parallel sections
    _ = az.host_admin_index # warm before parallel sections
    try:
        from adcontrol import adcs as adcs_mod
        adcs_mod.analyze_adcs(store, az)
    except Exception:
        pass
    now = datetime.datetime.now().isoformat(timespec="seconds")

    # Queries — independent of each other, run in parallel.
    def _run_query(entry):
        qid, label, desc = entry["id"], entry["label"], entry["description"]
        try:
            hits = q_mod.run_query(qid, store, az)
        except Exception:
            hits = []
        return qid, label, desc, hits

    query_entries = q_mod.list_queries()
    workers = min(8, len(query_entries) or 1)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        query_results = list(ex.map(_run_query, query_entries))

    query_html = []
    query_nav = []
    for qid, label, desc, hits in query_results:
        query_html.append(_query_section(qid, label, desc, hits))
        nav_count = sum(1 for h in hits if not h.get("expected"))
        query_nav.append(f'<a href="#q_{_esc(qid)}">{_esc(label)} '
                         f'<span class="ncount">{nav_count}</span></a>')

    paths_html = _paths_section(store, az)

    principals_html = ""
    principal_json = "[]"
    _data_tag_extra = ""
    has_principals = False
    if include_principals:
        # Users/groups/computers, plus GPOs — a GPO's inbound edges show who can
        # edit it (and thus push code to everything it's linked to), which is a
        # control relationship worth surfacing here.
        all_principals = [o for o in store.objects.values()
                          if o.object_class in ("user", "group", "computer",
                                                "groupPolicyContainer", "gpo")]
        # Keep only principals that actually have a control relationship — an
        # outbound edge (one of their effective SIDs holds an ACE) or an inbound
        # one (they carry a granting ACE / an owner). Leaf objects with neither
        # are pure size with no signal.
        idx = az.acl_index
        def has_edges(o):
            if any(sid in idx for sid in az.graph.effective_sids(o)):
                return True
            return any(not a.right.startswith("DENY:") for a in o.aces) or bool(o.owner_sid)
        interesting = sorted((o for o in all_principals if has_edges(o)),
                             key=lambda o: (o.object_class, o.label.lower()))
        if principal_cap is not None and len(interesting) > principal_cap:
            interesting = interesting[:principal_cap]
        # LAZY RENDER: the DOM gets only a light summary ROW per principal; the
        # full outbound/inbound tables are built on demand (see report JS) from
        # this JSON blob. This keeps a 10k-object domain instant — the browser is
        # no longer laying out thousands of collapsed tables up front.
        # _principal_data calls are read-only on store/az — safe to parallelize.
        pd_workers = min(8, len(interesting) or 1)
        with ThreadPoolExecutor(max_workers=pd_workers) as ex:
            data = list(ex.map(lambda o: _principal_data(store, az, o), interesting))
        has_principals = bool(data)
        principal_json = _json_blob(data)
        if len(principal_json) > _COMPRESS_THRESHOLD:
            _compressed = base64.b64encode(
                gzip.compress(principal_json.encode("utf-8"), compresslevel=6)
            ).decode("ascii")
            _data_tag_extra = ' data-gz="1"'
            principal_json = _compressed
        else:
            _data_tag_extra = ""
        principals_html = (
            '<section id="principals"><h3>Per-principal control '
            f'<span class="count">{len(data)}</span></h3>'
            '<p class="meta">Each principal\'s outbound (what it controls) and '
            'inbound (who controls it) edges. Detail loads when you open a row. '
            'Use the filter in the sidebar to find a principal.</p>'
            '<div id="prinlist"></div>'
            '<p class="none" id="prinempty" hidden>No principal here matches that '
            'filter. (This section lists only principals that have a control edge — '
            'someone with no inbound/outbound control won\'t appear.)</p>'
            '</section>')

    # Sidebar search — always visible while scrolling; filters the principal rows.
    sidebar_search = (
        '<div class="navsearch">'
        '<input id="pfilter" type="search" placeholder="Filter principals…" '
        'autocomplete="off" oninput="filterPrincipals(this.value)" '
        'aria-label="Filter principals by name, type, or DN">'
        '<span class="pcount" id="pfiltercount"></span></div>') if has_principals else ""
    nav = ('<nav class="toc"><b>Contents</b>'
           '<a href="#summary">Summary</a>'
           + "".join(query_nav)
           + '<a href="#paths">Attack paths to Tier-0</a>'
           + ('<a href="#principals">Per-principal control</a>' if include_principals else '')
           + sidebar_search
           + '</nav>')

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>adcontrol — {_esc(store.domain or 'domain')} report</title>
<style>
/* Token palette — cool-slate neutrals biased toward the blue accent, so greys
   read as chosen. Secondary text (--dim) is dark enough for AA on the ground
   (#55606e ≈ 7:1 on white). Themed at token level; data-theme overrides win. */
:root{{
  color-scheme:light dark;
  --bg:#f7f8fa; --panel:#ffffff; --ink:#161a20; --dim:#55606e;
  --line:#d4dae2; --line-soft:#e5e9ef; --chip:#efe9fb; --chip-ink:#4c2a86;
  --accent:#6d33d6; --crit:#d43d47; --crit-soft:#fbecec;
  --head:#4c2a86; --head-ink:#f3ecff;
}}
@media(prefers-color-scheme:dark){{:root{{
  --bg:#131519; --panel:#1b1e24; --ink:#e8eaee; --dim:#9aa4b2;
  --line:#2c3138; --line-soft:#24272e; --chip:#2a2340; --chip-ink:#c7b3f5;
  --accent:#a982f5; --crit:#f0616b; --crit-soft:#2a1c1e;
  --head:#5a37a0; --head-ink:#f0e9ff;
}}}}
:root[data-theme="light"]{{
  --bg:#f7f8fa; --panel:#ffffff; --ink:#161a20; --dim:#55606e;
  --line:#d4dae2; --line-soft:#e5e9ef; --chip:#efe9fb; --chip-ink:#4c2a86;
  --accent:#6d33d6; --crit:#d43d47; --crit-soft:#fbecec;
  --head:#4c2a86; --head-ink:#f3ecff;
}}
:root[data-theme="dark"]{{
  --bg:#131519; --panel:#1b1e24; --ink:#e8eaee; --dim:#9aa4b2;
  --line:#2c3138; --line-soft:#24272e; --chip:#2a2340; --chip-ink:#c7b3f5;
  --accent:#a982f5; --crit:#f0616b; --crit-soft:#2a1c1e;
  --head:#5a37a0; --head-ink:#f0e9ff;
}}
*{{box-sizing:border-box}}
body{{font:14px/1.55 system-ui,-apple-system,sans-serif;margin:0;background:var(--bg);color:var(--ink);
  display:grid;grid-template-columns:236px 1fr;min-height:100vh}}
@media(max-width:820px){{body{{grid-template-columns:1fr}} .toc{{position:static;height:auto}}}}
.toc{{position:sticky;top:0;align-self:start;height:100vh;overflow:auto;padding:1rem .8rem;
  background:var(--panel);border-right:1px solid var(--line);font-size:.82rem}}
.toc b{{display:block;margin-bottom:.5rem;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--dim)}}
.toc a{{display:flex;justify-content:space-between;gap:.4rem;padding:.3rem .45rem;border-radius:6px;
  color:var(--ink);text-decoration:none}}
.toc a:hover{{background:var(--chip)}}
.ncount{{background:var(--chip);color:var(--chip-ink);border-radius:99px;padding:0 .5em;font-size:.72rem;font-variant-numeric:tabular-nums}}
main{{padding:1.6rem 2rem;max-width:1200px}}
h1{{font-size:1.5rem;margin:0 0 .2rem;letter-spacing:-.01em}}
h3{{font-size:1.12rem;margin:2rem 0 .3rem;border-bottom:2px solid var(--line);padding-bottom:.35rem;letter-spacing:-.01em}}
h4{{font-size:.85rem;margin:1rem 0 .3rem;color:var(--dim);text-transform:uppercase;letter-spacing:.04em}}
code{{background:var(--chip);color:var(--chip-ink);padding:.1em .4em;border-radius:4px;font-size:.85em}}
.count{{background:var(--accent);color:#fff;border-radius:99px;padding:.08em .6em;font-size:.72rem;vertical-align:middle;font-variant-numeric:tabular-nums}}
.meta{{color:var(--dim);font-size:.85rem;margin:.2rem 0 .7rem}}
.mono{{font-family:ui-monospace,monospace;font-size:.8rem;color:var(--dim);word-break:break-all;margin:.2rem 0 .6rem}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}}
.card{{background:var(--panel);border:1px solid var(--line-soft);border-radius:10px;padding:.7rem 1.1rem;min-width:110px}}
.card b{{display:block;font-size:1.5rem;line-height:1;font-variant-numeric:tabular-nums}}
.card span{{font-size:.72rem;color:var(--dim);text-transform:uppercase;letter-spacing:.03em}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line-soft);
  border-radius:10px;overflow:hidden;font-size:.86rem;margin:.4rem 0 1rem}}
th,td{{text-align:left;padding:.45rem .65rem;border-bottom:1px solid var(--line-soft);vertical-align:top}}
tr:last-child td{{border-bottom:0}}
th{{background:var(--head);color:var(--head-ink);font-weight:600;font-size:.74rem;text-transform:uppercase;letter-spacing:.04em}}
.sev{{color:#fff;padding:.05em .5em;border-radius:99px;font-size:.72rem;text-transform:uppercase}}
.pill{{font-size:.68rem;text-transform:uppercase;letter-spacing:.02em;padding:.08em .55em;border-radius:99px;background:var(--chip);color:var(--chip-ink)}}
.pill.hi{{background:var(--crit-soft);color:var(--crit)}}
.pill.tk-direct{{background:var(--crit-soft);color:var(--crit)}}
.pill.tk-broad{{background:var(--chip);color:var(--dim)}}
.rt{{font-weight:600}} .scope{{color:var(--dim);font-size:.9em}} .right{{font-weight:600}}
.broad{{background:var(--crit);color:#fff;font-size:.65rem;padding:.05em .4em;border-radius:4px;margin-left:.3em}}
.none{{color:var(--dim);font-style:italic}}
.win{{font-weight:700;color:var(--crit)}}
.chain{{font-size:.82rem;color:var(--ink)}} .arw{{color:var(--dim)}}
/* Sidebar search — sticks with the nav, so it's always visible while scrolling. */
.navsearch{{position:sticky;bottom:0;margin-top:.8rem;padding-top:.6rem;
  border-top:1px solid var(--line);background:var(--panel)}}
#pfilter{{width:100%;padding:.45rem .6rem;font-size:.82rem;color:var(--ink);
  background:var(--bg);border:1px solid var(--line);border-radius:8px}}
#pfilter:focus{{outline:2px solid var(--accent);outline-offset:1px;border-color:var(--accent)}}
#pfilter::placeholder{{color:var(--dim)}}
.pcount{{display:block;color:var(--dim);font-size:.72rem;margin-top:.35rem;font-variant-numeric:tabular-nums}}
.qtoggle{{display:inline-flex;align-items:center;gap:.45rem;margin:.1rem 0 .7rem;
  font-size:.82rem;color:var(--dim);cursor:pointer;user-select:none}}
.qtoggle input{{accent-color:var(--accent);cursor:pointer}}
details.prin{{background:var(--panel);border:1px solid var(--line-soft);border-radius:10px;margin:.45rem 0;padding:.2rem .7rem}}
details.prin[hidden]{{display:none}}
mark{{background:var(--accent);color:#fff;border-radius:3px;padding:0 .1em}}
details.prin>summary{{cursor:pointer;padding:.45rem;font-weight:600;list-style:none}}
details.prin>summary::-webkit-details-marker{{display:none}}
details.prin>summary:hover{{color:var(--accent)}}
details.prin[open]>summary{{border-bottom:1px solid var(--line-soft);margin-bottom:.5rem}}
.tableWrap{{overflow-x:auto}}
</style></head><body>
{nav}
<main>
<h1>adcontrol — domain control report</h1>
<div class="meta">Generated {now} · source {_esc(store.source)} · domain
  <code>{_esc(store.domain)}</code></div>
<section id="summary">
<div class="cards">
  <div class="card"><b>{len(store)}</b><span>objects</span></div>
  <div class="card"><b>{len(store.principals())}</b><span>principals</span></div>
  <div class="card"><b>{sum(1 for o in store.objects.values() if o.object_class=='user')}</b><span>users</span></div>
  <div class="card"><b>{sum(1 for o in store.objects.values() if o.object_class=='group')}</b><span>groups</span></div>
  <div class="card"><b>{sum(1 for o in store.objects.values() if o.object_class=='computer')}</b><span>computers</span></div>
  <div class="card"><b>{len(getattr(store,'sessions',[]) or [])}</b><span>sessions</span></div>
</div>
</section>
{"".join(query_html)}
{paths_html}
{principals_html}
</main>
<script type="application/json" id="prindata"{_data_tag_extra}>{principal_json}</script>
<script>
// Named init so both the sync (inline JSON) and async (gzip+b64) paths can
// call it once data is ready. All DOM work lives here; the loader below handles
// how data arrives.
function _adcInit(data){{
  var host=document.getElementById('prinlist');
  if(!host) return;
  var empty=document.getElementById('prinempty');
  var counter=document.getElementById('pfiltercount');
  var total=data.length;
  var SEV={{h:'high',m:'medium',l:'low'}};
  var SEVC={{h:'#e5484d',m:'#e0a800',l:'#3a9e6a'}};
  function esc(s){{ return String(s==null?'':s).replace(/[&<>"]/g,function(c){{
    return {{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c]; }}); }}
  function edgeTable(edges,dir){{
    if(!edges.length) return '<p class="none">None.</p>';
    var who=dir==='out'?'Target':'Principal', rows='';
    for(var i=0;i<edges.length;i++){{ var e=edges[i];
      rows+='<tr><td><span class="sev" style="background:'+SEVC[e.s]+'">'+SEV[e.s]+'</span></td>'
        +'<td class="right">'+esc(e.r)+'</td>'
        +'<td>'+esc(e.w)+(e.b?' <span class="broad">BROAD</span>':'')+(e.n?' <span class="pill">built-in</span>':'')+'</td>'
        +'<td>'+esc(e.c)+'</td><td class="scope">'+esc(e.v)+'</td></tr>';
    }}
    return '<div class="tableWrap"><table><thead><tr><th>Sev</th><th>Right</th><th>'+who
      +'</th><th>Class</th><th>Via</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  }}
  function sessTable(sess){{
    if(!sess.length) return '';
    var rows='';
    for(var i=0;i<sess.length;i++) rows+='<tr><td><span class="pill">'+esc(sess[i].kind)
      +'</span></td><td>'+esc(sess[i].label)+'</td></tr>';
    return '<h4>Logon sessions</h4><div class="tableWrap"><table><tbody>'+rows+'</tbody></table></div>';
  }}
  function build(d){{
    return '<div class="mono">'+esc(d.dn)+'</div>'
      +'<h4>Outbound — can control ('+d.out.length+')</h4>'+edgeTable(d.out,'out')
      +'<h4>Inbound — controlled by ('+d['in'].length+')</h4>'+edgeTable(d['in'],'in')
      +sessTable(d.sess);
  }}
  var frag=document.createDocumentFragment();
  var rows=[];
  for(var i=0;i<data.length;i++){{ var d=data[i];
    var det=document.createElement('details');
    det.className='prin'; det._d=d;
    var badges='';
    if(d.oh) badges+=' <span class="pill hi" title="high-severity outbound edges — objects this principal can control">'+d.oh+' outbound</span>';
    if(d.ih) badges+=' <span class="pill hi" title="high-severity inbound edges — principals that can control this object">'+d.ih+' inbound</span>';
    det.innerHTML='<summary>'+esc(d.label)+' <span class="pill '+esc(d['class'])+'">'+esc(d['class'])
      +'</span>'+badges+'</summary><div class="lazybody"></div>';
    det.addEventListener('toggle',function(){{
      if(this.open && !this._built){{ this._built=1;
        this.querySelector('.lazybody').innerHTML=build(this._d); }}
    }});
    rows.push(det); frag.appendChild(det);
  }}
  host.appendChild(frag);
  function update(n){{ if(counter) counter.textContent = n===total ? total+' principals' : (n+' of '+total); }}
  update(total);
  window.filterPrincipals=function(q){{
    var terms=q.toLowerCase().split(/\\s+/).filter(Boolean);
    var shown=0;
    for(var i=0;i<rows.length;i++){{
      var ok=terms.every(function(t){{return rows[i]._d.q.indexOf(t)!==-1;}});
      rows[i].hidden=!ok; if(ok) shown++;
    }}
    if(empty) empty.hidden = shown!==0;
    update(shown);
  }};
}}
// Load principal data. Small domains inline plain JSON; large ones (> 500 KB)
// embed gzip+b64 and decompress with the native DecompressionStream API.
(function(){{
  var el=document.getElementById('prindata');
  if(!el) return;
  if(el.getAttribute('data-gz')){{
    var b64=el.textContent.trim(), bin=atob(b64);
    var arr=new Uint8Array(bin.length);
    for(var i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
    new Response(new Blob([arr]).stream().pipeThrough(new DecompressionStream('gzip')))
      .text().then(function(j){{ _adcInit(JSON.parse(j)); }}).catch(function(){{ _adcInit([]); }});
  }} else {{
    var d; try{{ d=JSON.parse(el.textContent); }}catch(e){{ d=[]; }}
    _adcInit(d);
  }}
}})();
window.toggleExpected=function(qid, show){{
  var sec=document.getElementById('q_'+qid);
  if(!sec) return;
  sec.querySelectorAll('details.prin.expected').forEach(function(d){{ d.hidden=!show; }});
  var em=sec.querySelector('[data-empty]');
  if(em) em.hidden = show;
}};
</script>
</body></html>"""
