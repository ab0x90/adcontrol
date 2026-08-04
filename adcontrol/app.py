"""
Flask + SocketIO web GUI for adcontrol.

Default port 5006.
Flow:
  1. POST /api/collect with DC + creds + auth options  -> background collect,
     progress streamed over SocketIO 'log' events, 'done' on completion.
  2. GET  /api/principals?q=  -> search collected principals.
  3. GET  /api/analyze/<key> -> {subject, outbound[], inbound[]} (kept separate).
  4. GET  /api/report/<key>?fmt=html|md -> downloadable scoped report.

The collected ObjectStore lives in memory for the process lifetime; a pickle is
also written to sessions/ so a collection can be reloaded without re-querying.
"""

from __future__ import annotations

import os
import pickle
import threading
import datetime

from flask import Flask, request, jsonify, Response, send_from_directory
from flask_socketio import SocketIO

from adcontrol.connection import LdapClient
from adcontrol import collector as collector_mod
from adcontrol.analyze import Analyzer
from adcontrol import report as report_mod
from adcontrol.model import ObjectStore
from adcontrol.smbauth import SmbCreds
from adcontrol import hostrights as hr_mod

BASE = os.path.dirname(os.path.abspath(__file__))
SESS_DIR = os.path.join(os.path.dirname(BASE), "adcontrol_sessions")
os.makedirs(SESS_DIR, exist_ok=True)

app = Flask(__name__, template_folder=os.path.join(BASE, "templates"))
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

STATE = {
    "store": None,        # type: ObjectStore | None
    "analyzer": None,     # type: Analyzer | None
    "collecting": False,
    "logs": [],
}

# Credentials/params supplied on the CLI, used to pre-fill the collect form and
# auto-start a collection on first page load. The real password is held here and
# never sent to the browser — the form receives a sentinel and /api/collect
# swaps it back in server-side.
PREFILL = {}
_PW_SENTINEL = "\x00__adcontrol_cli_pw__\x00"


def _emit_log(msg, level="info"):
    STATE["logs"].append({"msg": msg, "level": level})
    socketio.emit("log", {"msg": msg, "level": level})


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
        adcs_mod.analyze_adcs(store, az, log=_emit_log)
    except Exception as e:
        _emit_log(f"[adcs] analysis skipped: {e}", "warn")
    STATE["analyzer"] = az
    return az


def _run_collection(params):
    STATE["collecting"] = True
    STATE["logs"] = []
    try:
        client = LdapClient(
            dc=params["dc"], username=params["username"], password=params.get("password", ""),
            domain=params.get("domain", ""), nthash=params.get("nthash", ""),
            use_ldaps=params.get("ldaps", False), use_kerberos=params.get("kerberos", False),
            aes_key=params.get("aes_key", ""), dc_ip=params.get("dc_ip", ""),
            log=_emit_log,
        )
        if not client.connect():
            _emit_log("[collect] connection failed — aborting", "error")
            socketio.emit("done", {"ok": False})
            return

        do_gpo = params.get("gpo", True)
        host_mode = params.get("host_mode", "none")   # "none" | "all" | "list"
        hosts_spec = params.get("hosts", "")
        session_mode = params.get("session_mode", "none")   # "none" | "all" | "list"
        smb_creds = None
        if do_gpo or host_mode != "none" or session_mode != "none":
            smb_creds = SmbCreds(
                username=params["username"], password=params.get("password", ""),
                domain=client.domain, nthash=params.get("nthash", ""),
                use_kerberos=params.get("kerberos", False), aes_key=params.get("aes_key", ""),
                dc_ip=params.get("dc_ip", "") or client.dc_ip or "", log=_emit_log)

        store = collector_mod.collect(
            client, log=_emit_log, smb_creds=smb_creds, dc_host=params["dc"],
            dc_ip=params.get("dc_ip", "") or client.dc_ip or "",
            do_gpo=do_gpo, host_targets=None)
        client.close()

        # Tier 3 host plane, resolved after LDAP.
        if smb_creds and host_mode == "list" and hosts_spec:
            targets = hr_mod.hosts_from_spec(hosts_spec)
            hr_mod.collect_host_rights(store, smb_creds, targets, log=_emit_log)
        elif smb_creds and host_mode == "all":
            targets = hr_mod.hosts_from_store(store)
            hr_mod.collect_host_rights(store, smb_creds, targets, log=_emit_log)
        # Tier 3 live session plane, resolved after LDAP.
        if smb_creds and session_mode != "none":
            from adcontrol import sessions as sess_mod
            stargets = (hr_mod.hosts_from_spec(hosts_spec)
                        if session_mode == "list" and hosts_spec
                        else hr_mod.hosts_from_store(store))
            sess_mod.collect_sessions(store, smb_creds, stargets, log=_emit_log)
        STATE["store"] = store
        _set_analyzer(store)
        # Persist.
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(SESS_DIR, f"{store.domain or 'domain'}_{ts}.pkl")
        try:
            with open(path, "wb") as fh:
                pickle.dump(store, fh)
            _emit_log(f"[collect] session saved: {os.path.basename(path)}", "info")
        except Exception as e:
            _emit_log(f"[collect] session save failed: {e}", "warn")
        socketio.emit("done", {"ok": True, "count": len(store),
                               "principals": len(store.principals())})
    except Exception as e:
        _emit_log(f"[collect] error: {e}", "error")
        socketio.emit("done", {"ok": False})
    finally:
        STATE["collecting"] = False


@app.route("/")
def index():
    return send_from_directory(app.template_folder, "index.html")


@app.route("/api/status")
def status():
    store = STATE["store"]
    return jsonify({
        "collecting": STATE["collecting"],
        "collected": store is not None,
        "count": len(store) if store else 0,
        "principals": len(store.principals()) if store else 0,
        "domain": store.domain if store else "",
    })


@app.route("/api/prefill")
def prefill():
    """Values the GUI uses to pre-populate the collect form (and auto-start when
    CLI creds were supplied). Password is never included — the form uses the
    sentinel, which /api/collect swaps for the real value server-side."""
    if not PREFILL:
        return jsonify({"has_creds": False})
    return jsonify({
        "has_creds": True,
        "autostart": PREFILL.get("autostart", False),
        "dc": PREFILL.get("dc", ""),
        "username": PREFILL.get("username", ""),
        "domain": PREFILL.get("domain", ""),
        # sentinel stands in for a supplied password so the browser never sees it
        "password": _PW_SENTINEL if PREFILL.get("password") else "",
        "nthash": PREFILL.get("nthash", ""),
        "kerberos": PREFILL.get("kerberos", False),
        "ldaps": PREFILL.get("ldaps", False),
        "aes_key": PREFILL.get("aes_key", ""),
        "dc_ip": PREFILL.get("dc_ip", ""),
        "gpo": PREFILL.get("gpo", True),
        "host_mode": PREFILL.get("host_mode", "none"),
        "hosts": PREFILL.get("hosts", ""),
    })


@app.route("/api/collect", methods=["POST"])
def collect():
    if STATE["collecting"]:
        return jsonify({"error": "collection already running"}), 409
    params = request.get_json(force=True) or {}
    # Swap the password sentinel back to the real CLI-supplied secret.
    if params.get("password") == _PW_SENTINEL:
        params["password"] = PREFILL.get("password", "")
    if params.get("nthash") == _PW_SENTINEL:
        params["nthash"] = PREFILL.get("nthash", "")
    if not params.get("dc") or not params.get("username"):
        return jsonify({"error": "dc and username required"}), 400
    threading.Thread(target=_run_collection, args=(params,), daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/import-bloodhound", methods=["POST"])
def import_bloodhound():
    """Import a BloodHound zip. Accepts either an uploaded file (multipart 'file')
    or a server-side path in JSON {'path': ...}. Loads the store in-process."""
    from adcontrol import bloodhound as bh_mod
    src = None
    tmp = None
    try:
        if request.files.get("file"):
            up = request.files["file"]
            tmp = os.path.join(SESS_DIR, "_bh_upload.zip")
            up.save(tmp)
            src = tmp
        else:
            body = request.get_json(silent=True) or {}
            src = body.get("path", "")
        if not src or (tmp is None and not os.path.exists(src)):
            return jsonify({"error": "provide an uploaded file or a valid server path"}), 400
        STATE["logs"] = []
        store = bh_mod.import_zip(src, log=_emit_log)
        STATE["store"] = store
        _set_analyzer(store)
        # Persist as a session so it can be reloaded.
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            with open(os.path.join(SESS_DIR, f"bloodhound_{store.domain or 'import'}_{ts}.pkl"), "wb") as fh:
                pickle.dump(store, fh)
        except Exception:
            pass
        return jsonify({"ok": True, "count": len(store), "principals": len(store.principals()),
                        "domain": store.domain})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


@app.route("/api/sessions")
def sessions():
    out = []
    for f in sorted(os.listdir(SESS_DIR), reverse=True):
        if f.endswith(".pkl"):
            out.append(f)
    return jsonify({"sessions": out})


@app.route("/api/load-session", methods=["POST"])
def load_session():
    name = (request.get_json(force=True) or {}).get("name", "")
    path = os.path.join(SESS_DIR, os.path.basename(name))
    if not os.path.isfile(path):
        return jsonify({"error": "not found"}), 404
    try:
        with open(path, "rb") as fh:
            store = pickle.load(fh)
        STATE["store"] = store
        _set_analyzer(store)
        return jsonify({"ok": True, "count": len(store), "principals": len(store.principals()),
                        "domain": store.domain})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Map AD object_class values → the friendly filter/badge types the GUI uses.
_TYPE_MAP = {
    "user": "user",
    "group": "group",
    "computer": "computer",
    "groupPolicyContainer": "gpo",
    "organizationalUnit": "ou",
    "domain": "domain",
    "container": "container",
}
# Default set when no ?types= is given — preserves the original behaviour of
# only listing selectable principals (user/group/computer).
_DEFAULT_TYPES = ("user", "group", "computer")
# Every type the filter UI can request.
_ALL_TYPES = ("user", "group", "computer", "gpo", "ou", "domain", "container")


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


def _edge_json(e):
    return {"source_sid": e.source_sid, "source_label": e.source_label,
            "target_dn": e.target_dn, "target_label": e.target_label,
            "target_class": e.target_class, "right": e.right, "severity": e.severity,
            "applies_to": e.applies_to, "via": e.via, "inherited": e.inherited,
            "broad": e.broad, "builtin_noise": e.builtin_noise}


@app.route("/api/analyze/<path:key>")
def analyze(key):
    store, az = STATE["store"], STATE["analyzer"]
    if not store:
        return jsonify({"error": "nothing collected"}), 400
    subj = _resolve(store, key)
    if not subj:
        return jsonify({"error": "principal not found"}), 404
    s = az.summarize(subj)
    # Add the friendly type so the detail header badge matches the list badges.
    subject = dict(s["subject"])
    subject["object_class"] = subject.get("class", "")
    subject["class"] = _friendly_type(subject.get("class", ""))
    return jsonify({
        "subject": subject,
        "outbound": [_edge_json(e) for e in s["outbound"]],
        "inbound": [_edge_json(e) for e in s["inbound"]],
        "policy_rights": [{
            "plane": pr.plane, "right": pr.right, "trustees": pr.trustees,
            "applies_to": pr.applies_to, "source": pr.source, "severity": pr.severity,
        } for pr in s["policy_rights"]],
        "sessions": _sessions_json(store, subj),
        "local_admin_rdp": s["local_admin_rdp"],
        "adcs": s["adcs"],
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

    adv = advice_mod.advise(right)
    return jsonify({
        "right": right, "advice": adv,
        "chain": chain,
        "trustee_label": az.graph.label_for_sid(trustee_sid),
        "trustee_sid": trustee_sid,
        "target_dn": target_dn,
        "target_label": target.label if target else target_dn,
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


def run(host="127.0.0.1", port=5006, prefill=None, preloaded_store=None):
    if prefill:
        PREFILL.clear()
        PREFILL.update(prefill)
    if preloaded_store is not None:
        STATE["store"] = preloaded_store
        _set_analyzer(preloaded_store)
    socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True)
