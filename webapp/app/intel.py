"""Threat intel dashboard. Serves /intel; serves cached snapshot instantly,
refreshes from pipeline in a background thread when cache is stale.
The user never blocks on the pipeline, and never sees an empty page if a
cache file exists."""
from __future__ import annotations
import fcntl
import gzip
import json
import os
import threading
import time
import httpx
from pathlib import Path
from flask import Blueprint, Response, request

intel_bp = Blueprint("intel", __name__)

PIPELINE_URL = os.environ["PIPELINE_URL"].rstrip("/")
PIPELINE_SERVICE_TOKEN = os.environ["PIPELINE_SERVICE_TOKEN"]
CACHE_FILE   = Path("/opt/webapp/data/intel_snapshot.json")
CACHE_TTL_S  = 3600

_refresh_lock = threading.Lock()


def _fetch_snapshot() -> dict:
    r = httpx.get(
        f"{PIPELINE_URL}/knowledge/dashboard_snapshot",
        headers={"X-Pipeline-Service-Token": PIPELINE_SERVICE_TOKEN},
        timeout=60.0,
    )
    r.raise_for_status()
    return r.json()


def _atomic_write(data: dict) -> None:
    tmp = CACHE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, CACHE_FILE)


def _do_refresh() -> None:
    """Cross-process locked refresh. Only one gunicorn worker actually fetches."""
    lock_path = CACHE_FILE.with_suffix(".json.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return  # another worker is already refreshing
        try:
            _atomic_write(_fetch_snapshot())
        except Exception:
            pass  # keep stale cache on failure
    finally:
        os.close(fd)


def _refresh_async() -> None:
    """Fire-and-forget refresh from a daemon thread."""
    if not _refresh_lock.acquire(blocking=False):
        return
    try:
        threading.Thread(target=_do_refresh, daemon=True).start()
    finally:
        _refresh_lock.release()


_EMPTY_SNAPSHOT = {
    "generated_ts": 0,
    "generated_at": "",
    "stats": {"techniques": 0, "cves_loaded": 0, "playbooks": 0},
    "techniques": [],
    "cves_top": [],
    "recent_cves": [],
    "cwe_top": [],
    "playbooks": [],
    "cwe_remediation": {},
    "news": [],
}


def get_snapshot() -> dict:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Fast path: cache exists -> return it immediately (stale or not).
    if CACHE_FILE.is_file():
        try:
            age = time.time() - CACHE_FILE.stat().st_mtime
            data = json.loads(CACHE_FILE.read_text())
            if age > CACHE_TTL_S:
                _refresh_async()
            return data
        except Exception:
            pass  # corrupt cache; fall through to fresh fetch

    # Cold path: no cache at all. Block on fetch, but never 500.
    try:
        snap = _fetch_snapshot()
        _atomic_write(snap)
        return snap
    except Exception:
        return dict(_EMPTY_SNAPSHOT, generated_ts=int(time.time()))


@intel_bp.route("/intel")
def intel_page():
    from flask import render_template
    return render_template("intel.html", intel_mode=True)


@intel_bp.route("/intel/snapshot.json")
def intel_snapshot():
    raw = json.dumps(get_snapshot()).encode("utf-8")
    accepts_gz = "gzip" in (request.headers.get("Accept-Encoding") or "")
    if accepts_gz:
        return Response(gzip.compress(raw), mimetype="application/json",
                        headers={"Content-Encoding": "gzip"})
    return Response(raw, mimetype="application/json")
