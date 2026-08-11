"""
Flask web GUI for adcontrol — READ-ONLY viewer/reporter.

This process never gathers data itself; all collection lives in
`adcontrol_scan.py`, which writes finished runs to loot/<run_id>/. This app
only ever loads a run from there for browsing/reporting.

Flow:
  1. GET  /api/runs -> list loot/<run_id>/ runs available to load.
  2. POST /api/load-run {run_id} -> load a run's ObjectStore into memory.
  3. GET  /api/principals?q=  -> search the loaded run's principals.
  4. GET  /api/analyze/<key> -> {subject, outbound[], inbound[]} (kept separate).
  5. GET  /api/report/<key>?fmt=html|md -> downloadable scoped report.
"""

from __future__ import annotations

import os

from flask import Flask, request, jsonify, Response, send_from_directory

from adcontrol.analyze import Analyzer
from adcontrol import report as report_mod
from adcontrol.model import ObjectStore
from adcontrol import loot

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)

app = Flask(__name__, template_folder=os.path.join(BASE, "templates"))

STATE = {
    "store": None,        # type: ObjectStore | None
    "analyzer": None,     # type: Analyzer | None
    "run_id": None,        # type: str | None
    "load_log": [],        # messages from the most recent run load (e.g. ADCS analysis)
}


def _load_log(msg, level="info"):
    STATE["load_log"].append({"msg": msg, "level": level})


def _set_analyzer(store, warm=True):
    """Install a fresh Analyzer for `store` and (by default) warm its reverse
    ACL index up front, so the first query is instant instead of paying the
    one-time index build. Safe to call from any load path."""
    az = Analyzer(store)
    if warm:
        try:
            _ = az.acl_index  # build the trustee->edges index once
        except Exception:
            pass
    try:
        from adcontrol import adcs as adcs_mod
        adcs_mod.analyze_adcs(store, az, log=_load_log)
    except Exception as e:
        _load_log(f"[adcs] analysis skipped: {e}", "warn")
    STATE["analyzer"] = az
    return az


def _load_run(run_id: str):
    """Load a loot run by ID into STATE. Returns (ok, error_or_None)."""
    run_dir = loot.run_dir_for(ROOT, run_id)
    if not run_dir:
        return False, "run not found"
    try:
        store = loot.load_store(run_dir)
    except Exception as e:
        return False, str(e)
    STATE["load_log"] = []
    STATE["store"] = store
    STATE["run_id"] = run_id
    _set_analyzer(store)
    return True, None


def load_run_for_cli(run_id: str):
    """Load a loot run and return (store, analyzer) for no-GUI report generation
    (see adcontrol_web.py --subject / --offline-report). Raises ValueError on
    failure; does not touch the web server's STATE."""
    run_dir = loot.run_dir_for(ROOT, run_id)
    if not run_dir:
        raise ValueError(f"run not found: {run_id}")
    store = loot.load_store(run_dir)
    az = _set_analyzer(store)
    return store, az


@app.route("/")
def index():
    return send_from_directory(app.template_folder, "index.html")


@app.route("/api/status")
def status():
    store = STATE["store"]
    return jsonify({
        "collected": store is not None,
        "run_id": STATE["run_id"],
        "count": len(store) if store else 0,
        "principals": len(store.principals()) if store else 0,
        "domain": store.domain if store else "",
    })


@app.route("/api/runs")
def runs():
    """Loot runs available to load, newest first."""
    return jsonify({"runs": loot.list_runs(ROOT)})


@app.route("/api/load-run", methods=["POST"])
def load_run():
    run_id = (request.get_json(force=True) or {}).get("run_id", "")
    if not run_id:
        return jsonify({"error": "run_id required"}), 400
    ok, err = _load_run(run_id)
    if not ok:
        return jsonify({"error": err}), 404
    store = STATE["store"]
    return jsonify({"ok": True, "count": len(store), "principals": len(store.principals()),
                    "domain": store.domain, "run_id": run_id, "log": STATE["load_log"]})


# Map AD object_class values → the friendly filter/badge types the GUI uses.
_TYPE_MAP = {
    "user": "user",
    "group": "group",
    "computer": "computer",
    "groupPolicyContainer": "gpo",
    "organizationalUnit": "ou",
    "domain": "domain",
    "container": "container",
    "pKICertificateTemplate": "template",
    "pKIEnrollmentService": "ca",
}
# Default set when no ?types= is given — preserves the original behaviour of
# only listing selectable principals (user/group/computer).
_DEFAULT_TYPES = ("user", "group", "computer")
# Every type the filter UI can request.
_ALL_TYPES = ("user", "group", "computer", "gpo", "ou", "domain", "container", "template", "ca")


def _friendly_type(object_class: str) -> str:
    return _TYPE_MAP.get(object_class, "other")


@app.route("/api/principals")
def principals():
    store = STATE["store"]
    if not store:
        return jsonify({"error": "nothing collected"}), 400
    q = request.args.get("q", "").strip()

    # ?types=user,group,gpo … filters by friendly type. Absent → default set.
    types_arg = request.args.get("types", "").strip()
    if types_arg:
        wanted = {t.strip().lower() for t in types_arg.split(",") if t.strip()}
        wanted &= set(_ALL_TYPES)
    else:
        wanted = set(_DEFAULT_TYPES)

    src = store.find(q) if q else list(store.objects.values())
    src = [o for o in src if _friendly_type(o.object_class) in wanted]
    src.sort(key=lambda o: (_friendly_type(o.object_class), o.label.lower()))
    return jsonify({
        "principals": [
            {"key": o.sid or o.dn, "label": o.label,
             "class": _friendly_type(o.object_class), "object_class": o.object_class,
             "dn": o.dn, "enabled": o.enabled, "admin_count": o.admin_count}
            for o in src[:500]
        ],
        # Per-type counts across the whole store, so the UI can show badges even
        # for types not currently selected.
        "counts": _type_counts(store),
    })


def _type_counts(store) -> dict:
    counts = {t: 0 for t in _ALL_TYPES}
    for o in store.objects.values():
        ft = _friendly_type(o.object_class)
        if ft in counts:
            counts[ft] += 1
    return counts


@app.route("/api/queries")
def queries_list():
    """The canned queries available in the Queries panel."""
    from adcontrol import queries as q_mod
    return jsonify({"queries": q_mod.list_queries()})


@app.route("/api/query/<query_id>")
def queries_run(query_id):
    """Run a canned query across the whole store; returns principal-list rows."""
    from adcontrol import queries as q_mod
    store, az = STATE["store"], STATE["analyzer"]
    if not store or not az:
        return jsonify({"error": "nothing collected"}), 400
    try:
        hits = q_mod.run_query(query_id, store, az)
    except KeyError:
        return jsonify({"error": f"unknown query: {query_id}"}), 404
    return jsonify({"query": query_id, "count": len(hits), "results": hits})


def _resolve(store, key):
    return store.by_sid(key) or store.by_dn(key)


def _edge_json(e, tier0_map=None):
    return {"source_sid": e.source_sid, "source_label": e.source_label,
            "target_dn": e.target_dn, "target_label": e.target_label,
            "target_class": e.target_class, "right": e.right, "severity": e.severity,
            "applies_to": e.applies_to, "via": e.via, "inherited": e.inherited,
            "broad": e.broad, "builtin_noise": e.builtin_noise,
            "target_tier0": (tier0_map or {}).get(e.target_dn)}


@app.route("/api/analyze/<path:key>")
def analyze(key):
    store, az = STATE["store"], STATE["analyzer"]
    if not store:
        return jsonify({"error": "nothing collected"}), 400
    subj = _resolve(store, key)
    if not subj:
        return jsonify({"error": "principal not found"}), 404
    s = az.summarize(subj)
    tier0_map = az.tier0_targets()
    # Add the friendly type so the detail header badge matches the list badges.
    subject = dict(s["subject"])
    subject["object_class"] = subject.get("class", "")
    subject["class"] = _friendly_type(subject.get("class", ""))
    return jsonify({
        "subject": subject,
        "outbound": [_edge_json(e, tier0_map) for e in s["outbound"]],
        "inbound": [_edge_json(e, tier0_map) for e in s["inbound"]],
        "policy_rights": [{
            "plane": pr.plane, "right": pr.right, "trustees": pr.trustees,
            "applies_to": pr.applies_to, "source": pr.source, "severity": pr.severity,
        } for pr in s["policy_rights"]],
        "sessions": _sessions_json(store, subj),
        "local_admin_rdp": s["local_admin_rdp"],
        "gpo_scope": s["gpo_scope"],
        "adcs": s["adcs"],
        "template_detail": s["template_detail"],
        "ca_detail": s["ca_detail"],
        "outbound_high": s["outbound_high"], "inbound_high": s["inbound_high"],
        "effective_group_count": s["effective_group_count"],
    })


def _sessions_json(store, subj):
    """Logon sessions relevant to the subject: for a computer, who is logged on;
    for a user, where they are logged on. Each row resolves the *other* end to a
    selectable key so the GUI can click through to it."""
    rows = []
    if subj.object_class == "computer" and subj.sid:
        for sess in store.sessions_on_host(subj.sid):
            u = store.by_sid(sess.user_sid)
            rows.append({"key": (u.sid or u.dn) if u else sess.user_sid,
                         "label": u.label if u else sess.user_sid,
                         "object_class": u.object_class if u else "",
                         "kind": sess.kind, "role": "user on this host"})
    elif subj.object_class == "user" and subj.sid:
        for sess in store.sessions_of_user(subj.sid):
            c = store.by_sid(sess.computer_sid)
            rows.append({"key": (c.sid or c.dn) if c else sess.computer_sid,
                         "label": c.label if c else sess.computer_sid,
                         "object_class": c.object_class if c else "",
                         "kind": sess.kind, "role": "host this user is on"})
    # Reliable sessions first, then by label.
    order = {"privileged": 0, "registry": 1, "netsession": 2}
    rows.sort(key=lambda r: (order.get(r["kind"], 9), r["label"].lower()))
    return rows


@app.route("/api/members/<path:key>")
def members(key):
    """Transitive members of a group, for the 'View members' modal. Each member
    row is a selectable principal (its ``key`` loads that member's own analysis).
    ``direct`` marks members that are direct (not only nested) members."""
    store, az = STATE["store"], STATE["analyzer"]
    if not store or not az:
        return jsonify({"error": "nothing collected"}), 400
    grp = _resolve(store, key)
    if not grp:
        return jsonify({"error": "principal not found"}), 404
    if grp.object_class != "group":
        return jsonify({"error": "not a group"}), 400

    # Direct-child DNs (both membership directions) → mark direct vs nested-only.
    direct_dns = az.graph._children_of(grp.dn)
    direct_sids = set()
    for dn in direct_dns:
        m = store.by_dn(dn)
        if m and m.sid:
            direct_sids.add(m.sid)

    sids = az.graph.member_sids_of(grp)
    rows = []
    for sid in sids:
        m = store.by_sid(sid)
        if m is None:
            rows.append({"key": sid, "label": az.graph.label_for_sid(sid),
                         "class": "other", "object_class": "", "enabled": True,
                         "admin_count": 0, "direct": sid in direct_sids})
        else:
            rows.append({"key": m.sid or m.dn, "label": m.label,
                         "class": _friendly_type(m.object_class),
                         "object_class": m.object_class, "enabled": m.enabled,
                         "admin_count": m.admin_count, "direct": sid in direct_sids})
    # Groups first (so nested groups are easy to drill into), then class, then name.
    rows.sort(key=lambda x: (x["class"] != "group", x["class"], x["label"].lower()))
    return jsonify({
        "group": {"label": grp.label, "key": grp.sid or grp.dn, "dn": grp.dn},
        "member_count": len(rows),
        "direct_count": sum(1 for r in rows if r["direct"]),
        "members": rows,
    })


@app.route("/api/paths/<path:key>")
def paths(key):
    """Multi-hop attack paths from the subject to the Tier-0 goal set (or an
    explicit ?target=<dn>). ?mode=short (default, BFS shortest) | full (all
    simple paths, count-capped) | full-uncapped (no count cap, wall-clock
    backstop only — can be slow/large on a dense graph). The response carries a
    ``truncated`` flag when enumeration stopped early."""
    store, az = STATE["store"], STATE["analyzer"]
    if not store or not az:
        return jsonify({"error": "nothing collected"}), 400
    subj = _resolve(store, key)
    if not subj:
        return jsonify({"error": "principal not found"}), 404
    from adcontrol.paths import PathFinder
    mode = request.args.get("mode", "short")
    target = request.args.get("target") or None
    pf = PathFinder(az)
    already = pf.already_tier0(subj) if not target else False
    result = pf.find_result(subj, mode=mode, target_dn=target)
    return jsonify({
        "subject": {"label": subj.label, "sid": subj.sid, "dn": subj.dn},
        "mode": mode,
        "already_tier0": already,
        "count": len(result.paths),
        "truncated": result.truncated,
        "truncated_reason": result.reason,
        "truncated_limit": result.limit,
        "paths": [p.as_json() for p in result.paths],
    })


@app.route("/api/edge-detail", methods=["POST"])
def edge_detail():
    """Full detail for a single control edge, for the modal: the membership chain
    the right is held through (nodes source→group(s)→holder→target), per-right
    offense/defense advice, and the raw ACE facts."""
    store, az = STATE["store"], STATE["analyzer"]
    if not store:
        return jsonify({"error": "nothing collected"}), 400
    from adcontrol import advice as advice_mod
    body = request.get_json(force=True) or {}
    subject_key = body.get("subject_key", "")
    target_dn = body.get("target_dn", "")
    right = body.get("right", "")
    trustee_sid = body.get("source_sid", "")
    direction = body.get("direction", "out")   # "out" | "in"

    subj = _resolve(store, subject_key)
    target = store.by_dn(target_dn)
    if not subj:
        return jsonify({"error": "subject not found"}), 404

    # Build the chain of nodes: for outbound, subject → ...groups... → holder,
    # then the target. For inbound, the trustee (holder) → target(subject).
    def node(o, role, note=""):
        return {"label": o.label, "sid": o.sid, "dn": o.dn,
                "class": o.object_class, "role": role, "note": note}

    # Under-box notes describe each node's ROLE; the arrows carry the
    # relationship ("member of" / the right), so notes avoid duplicating that.
    chain = []
    if direction == "out":
        holder = store.by_sid(trustee_sid)
        path = az.graph.membership_path(subj, trustee_sid) if holder else []
        if path:
            multi = len(path) > 1
            for i, o in enumerate(path):
                if i == 0:
                    role, note = "source", "this principal"
                elif i == len(path) - 1:
                    role, note = "holder", ("holds the right" if multi else "this principal")
                else:
                    role, note = "group", "via group"
                chain.append(node(o, role, note))
        else:
            # Held directly, or trustee is a well-known/broad group not in store.
            hlabel = az.graph.label_for_sid(trustee_sid)
            if holder and holder.dn == subj.dn:
                chain.append(node(subj, "source", "this principal"))  # direct
            else:
                chain.append(node(subj, "source", "this principal"))
                chain.append({"label": hlabel, "sid": trustee_sid,
                              "dn": holder.dn if holder else "",
                              "class": holder.object_class if holder else "group",
                              "role": "holder", "note": "holds the right"})
        if target:
            chain.append(node(target, "target", "target"))
    else:  # inbound: holder → subject
        hlabel = az.graph.label_for_sid(trustee_sid)
        holder = store.by_sid(trustee_sid)
        chain.append({"label": hlabel, "sid": trustee_sid,
                      "dn": holder.dn if holder else "",
                      "class": holder.object_class if holder else "group",
                      "role": "holder", "note": "holds the right"})
        chain.append(node(subj, "target", "this object"))

    tier0_map = az.tier0_targets()
    target_tier0 = tier0_map.get(target_dn)
    for n in chain:
        if n.get("role") == "target" and target_tier0:
            n["tier0"] = target_tier0

    adv = advice_mod.advise(right)
    return jsonify({
        "right": right, "advice": adv,
        "chain": chain,
        "trustee_label": az.graph.label_for_sid(trustee_sid),
        "trustee_sid": trustee_sid,
        "target_dn": target_dn,
        "target_label": target.label if target else target_dn,
        "target_tier0": target_tier0,
    })


@app.route("/api/report/<path:key>")
def report(key):
    store, az = STATE["store"], STATE["analyzer"]
    if not store:
        return jsonify({"error": "nothing collected"}), 400
    subj = _resolve(store, key)
    if not subj:
        return jsonify({"error": "principal not found"}), 404
    fmt = request.args.get("fmt", "html")
    safe = (subj.sam or subj.name or "object").replace(" ", "_")
    if fmt == "md":
        body = report_mod.to_markdown(store, subj, az)
        return Response(body, mimetype="text/markdown", headers={
            "Content-Disposition": f'attachment; filename="adcontrol_{safe}.md"'})
    body = report_mod.to_html(store, subj, az)
    return Response(body, mimetype="text/html", headers={
        "Content-Disposition": f'attachment; filename="adcontrol_{safe}.html"'})


def run(host="127.0.0.1", port=5006, initial_run=None):
    """Start the read-only viewer. *initial_run* (a run_id) is loaded once at
    startup only — a scan started after the server is already running won't
    appear until it's picked from the run dropdown or the server is restarted."""
    if initial_run:
        ok, err = _load_run(initial_run)
        if not ok:
            print(f"[!] could not load run {initial_run}: {err}")
    app.run(host=host, port=port)
