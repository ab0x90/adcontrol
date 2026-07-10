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
        smb_creds = None
        if do_gpo or host_mode != "none":
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
        STATE["store"] = store
        STATE["analyzer"] = Analyzer(store)
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
        STATE["analyzer"] = Analyzer(store)
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
        STATE["analyzer"] = Analyzer(store)
        return jsonify({"ok": True, "count": len(store), "principals": len(store.principals()),
                        "domain": store.domain})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/principals")
def principals():
    store = STATE["store"]
    if not store:
        return jsonify({"error": "nothing collected"}), 400
    q = request.args.get("q", "").strip()
    src = store.find(q) if q else store.principals()
    src = [o for o in src if o.object_class in ("user", "group", "computer")]
    src.sort(key=lambda o: (o.object_class, o.label.lower()))
    return jsonify({"principals": [
        {"key": o.sid or o.dn, "label": o.label, "class": o.object_class,
         "dn": o.dn, "enabled": o.enabled, "admin_count": o.admin_count}
        for o in src[:500]
    ]})


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
    return jsonify({
        "subject": s["subject"],
        "outbound": [_edge_json(e) for e in s["outbound"]],
        "inbound": [_edge_json(e) for e in s["inbound"]],
        "policy_rights": [{
            "plane": pr.plane, "right": pr.right, "trustees": pr.trustees,
            "applies_to": pr.applies_to, "source": pr.source, "severity": pr.severity,
        } for pr in s["policy_rights"]],
        "outbound_high": s["outbound_high"], "inbound_high": s["inbound_high"],
        "effective_group_count": s["effective_group_count"],
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
        STATE["analyzer"] = Analyzer(preloaded_store)
    socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True)
