"""
Loot storage for adcontrol_scan.py runs.

Every scan / offline import gets its own directory:

    <project_root>/loot/<run_id>/
        meta.json   run metadata (mode, target, timestamps, tiers, counts —
                    never credentials)
        store.pkl   pickled ObjectStore

``adcontrol_web.py`` (via adcontrol/app.py) never gathers data itself — it only
ever reads these directories to load a run for viewing/reporting.
"""

from __future__ import annotations

import json
import os
import pickle
from datetime import datetime

_LOOT_DIRNAME = "loot"


def loot_base(root: str) -> str:
    return os.path.join(root, _LOOT_DIRNAME)


def new_run_dir(root: str) -> tuple[str, str]:
    """Create and return (run_id, run_dir) for a fresh run."""
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(loot_base(root), run_id)
    os.makedirs(run_dir, exist_ok=True)
    return run_id, run_dir


def _atomic_write(path: str, data: bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def save_meta(run_dir: str, meta: dict):
    path = os.path.join(run_dir, "meta.json")
    _atomic_write(path, json.dumps(meta, indent=2, default=str).encode("utf-8"))


def load_meta(run_dir: str) -> dict:
    path = os.path.join(run_dir, "meta.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_store(run_dir: str, store):
    path = os.path.join(run_dir, "store.pkl")
    _atomic_write(path, pickle.dumps(store))


def load_store(run_dir: str):
    path = os.path.join(run_dir, "store.pkl")
    with open(path, "rb") as fh:
        return pickle.load(fh)


def run_dir_for(root: str, run_id: str) -> str | None:
    """Resolve *run_id* to a valid, loadable run directory, or None."""
    run_dir = os.path.join(loot_base(root), os.path.basename(run_id))
    if os.path.isdir(run_dir) and os.path.isfile(os.path.join(run_dir, "store.pkl")):
        return run_dir
    return None


def list_runs(root: str) -> list[dict]:
    """Summary dicts for every completed run under loot/, newest first."""
    base = loot_base(root)
    if not os.path.isdir(base):
        return []
    out = []
    for name in os.listdir(base):
        run_dir = os.path.join(base, name)
        if not os.path.isdir(run_dir) or not os.path.isfile(os.path.join(run_dir, "store.pkl")):
            continue
        meta = load_meta(run_dir)
        out.append({
            "run_id": name,
            "started_at": meta.get("started_at", ""),
            "ended_at": meta.get("ended_at", ""),
            "mode": meta.get("mode", ""),
            "target": meta.get("target", ""),
            "domain": meta.get("domain", ""),
            "object_count": meta.get("object_count", 0),
            "principal_count": meta.get("principal_count", 0),
        })
    out.sort(key=lambda r: r.get("started_at") or r["run_id"], reverse=True)
    return out


def latest_run(root: str) -> dict | None:
    runs = list_runs(root)
    return runs[0] if runs else None
