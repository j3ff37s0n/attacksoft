"""Pipeline internal API. Webapp-only, service-auth on every request.

Endpoints:
  POST /submissions                                  create a submission
  GET  /submissions/{webapp_submission_id}           read state
  GET  /submissions/{webapp_submission_id}/reports/{type}   stream PDF
  GET  /submissions?state=&updated_since=            reconciliation sweep
  GET  /health                                       service health
  GET  /knowledge/status                             knowledge base counts
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, Header, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse, Response
import subprocess
import sys
import io
import tarfile

from app import db

log = logging.getLogger(__name__)

UPLOADS_ROOT = Path("/opt/pipeline/data/uploads")
REPORTS_ROOT = Path("/opt/pipeline/data/reports")
SERVICE_TOKEN_FILE = Path("/opt/pipeline/config/service_token")
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
VALID_REPORT_TYPES = {"executive_risk", "timeline_attack_chain", "remediation"}

_log = logging.getLogger("uvicorn.error")


def _load_service_token() -> str:
    env = os.environ.get("PIPELINE_SERVICE_TOKEN", "").strip()
    if env:
        return env
    if SERVICE_TOKEN_FILE.is_file():
        return SERVICE_TOKEN_FILE.read_text().strip()
    raise RuntimeError(
        "PIPELINE_SERVICE_TOKEN not set and no service_token file at "
        f"{SERVICE_TOKEN_FILE}; refusing to start"
    )


SERVICE_TOKEN = _load_service_token()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_filename(name: str) -> str:
    if not name:
        return "sample.bin"
    base = Path(name).name
    base = "".join(c for c in base if c.isprintable() and c not in '/\\\x00')[:200]
    return base or "sample.bin"


def _require_service_token(x_pipeline_service_token: Optional[str]):
    if not x_pipeline_service_token:
        raise HTTPException(403, "missing X-Pipeline-Service-Token")
    if not hmac.compare_digest(x_pipeline_service_token, SERVICE_TOKEN):
        raise HTTPException(403, "invalid service token")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    UPLOADS_ROOT.mkdir(parents=True, exist_ok=True)
    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
    _log.info("pipeline-api starting; uploads=%s reports=%s", UPLOADS_ROOT, REPORTS_ROOT)
    yield
    _log.info("pipeline-api shutting down")


app = FastAPI(title="pipeline-internal", lifespan=lifespan, docs_url=None, redoc_url=None)


# ----------------------------- POST /submissions -----------------------------

@app.post("/submissions", status_code=status.HTTP_202_ACCEPTED)
async def create_submission(
    user_id: str = Form(...),
    webapp_submission_id: str = Form(...),
    callback_url: str = Form(...),
    platform: Optional[str] = Form(None),
    url: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    trace_id: Optional[str] = Form(None),
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    x_pipeline_service_token: Optional[str] = Header(None, alias="X-Pipeline-Service-Token"),
) -> dict:
    _require_service_token(x_pipeline_service_token)
    if not user_id:
        raise HTTPException(400, "user_id required")
    try:
        uuid.UUID(webapp_submission_id)
    except ValueError:
        raise HTTPException(400, "webapp_submission_id must be a UUID")
    if file is None and not url:
        raise HTTPException(400, "either file or url required")
    if file is not None and url:
        raise HTTPException(400, "provide file or url, not both")

    if platform is not None:
        platform = platform.strip().lower()
        if platform in ("", "auto"):
            platform = None
        elif platform not in ("windows", "linux"):
            raise HTTPException(400, "platform must be windows, linux, or auto")

    pipeline_submission_id = str(uuid.uuid4())
    trace_id = trace_id or str(uuid.uuid4())
    analysis_date = datetime.now(timezone.utc).strftime("%Y%m%d")
    artifact_root = f"pending/{webapp_submission_id}"

    row, created = db.insert_or_get(
        webapp_submission_id=webapp_submission_id,
        pipeline_submission_id=pipeline_submission_id,
        user_id=user_id,
        idempotency_key=idempotency_key,
        callback_url=callback_url,
        artifact_root=artifact_root,
        analysis_date=analysis_date,
        trace_id=trace_id,
        requested_platform=platform,
    )

    if not created:
        _log.info("idempotent replay sid=%s user=%s", webapp_submission_id, user_id)
        return {
            "webapp_submission_id": row["webapp_submission_id"],
            "pipeline_submission_id": row["pipeline_submission_id"],
            "state": row["state"],
            "trace_id": row["trace_id"],
            "requested_platform": row.get("requested_platform"),
            "idempotent_replay": True,
        }

    target_dir = UPLOADS_ROOT / webapp_submission_id
    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        if file is not None:
            target = target_dir / _safe_filename(file.filename or "sample.bin")
            total = 0
            with target.open("wb") as f:
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_UPLOAD_BYTES:
                        f.close()
                        target.unlink(missing_ok=True)
                        raise HTTPException(413, f"upload exceeds {MAX_UPLOAD_BYTES} bytes")
                    f.write(chunk)
            if total == 0:
                raise HTTPException(400, "uploaded file is empty")
            _log.info("staged file sid=%s bytes=%d name=%s", webapp_submission_id, total, target.name)
        else:
            (target_dir / "url.txt").write_text(url)
            _log.info("staged url sid=%s url=%s", webapp_submission_id, url[:200])
    except HTTPException:
        try:
            db.set_state(webapp_submission_id, "failed_extraction",
                         error_code="upload_rejected")
        except Exception:
            pass
        raise
    except Exception as exc:
        _log.exception("upload staging failed sid=%s", webapp_submission_id)
        try:
            db.set_state(webapp_submission_id, "failed_extraction",
                         error_code="upload_staging_error")
        except Exception:
            pass
        raise HTTPException(500, f"upload staging failed: {exc}")

    return {
        "webapp_submission_id": row["webapp_submission_id"],
        "pipeline_submission_id": row["pipeline_submission_id"],
        "state": row["state"],
        "trace_id": row["trace_id"],
        "requested_platform": row.get("requested_platform"),
        "idempotent_replay": False,
    }


# ----------------------------- GET /submissions/{id} -----------------------------

@app.get("/submissions/{webapp_submission_id}")
def get_submission(
    webapp_submission_id: str,
    user_id: str = Query(...),
    x_pipeline_service_token: Optional[str] = Header(None, alias="X-Pipeline-Service-Token"),
) -> dict:
    _require_service_token(x_pipeline_service_token)
    row = db.get_for_user(webapp_submission_id, user_id)
    if row is None:
        raise HTTPException(404, "not found or not authorized")
    out = dict(row)
    out.pop("idempotency_key", None)
    return out


# ----------------------------- GET /submissions/{id}/reports/{type} -----------------------------

@app.get("/submissions/{webapp_submission_id}/reports/{report_type}")
def get_report(
    webapp_submission_id: str,
    report_type: str,
    user_id: str = Query(...),
    x_pipeline_service_token: Optional[str] = Header(None, alias="X-Pipeline-Service-Token"),
):
    _require_service_token(x_pipeline_service_token)
    if report_type not in VALID_REPORT_TYPES:
        raise HTTPException(400, f"unknown report type: {report_type}")
    row = db.get_for_user(webapp_submission_id, user_id)
    if row is None:
        raise HTTPException(404, "not found or not authorized")

    state = row["state"]
    if state != "complete":
        if state.startswith("failed_"):
            raise HTTPException(
                410,
                detail=f"analysis failed: {row.get('error_code') or state}",
            )
        raise HTTPException(
            409,
            detail=f"analysis not complete; state={state}",
        )

    manifest = row.get("report_manifest_json") or []
    for entry in manifest:
        if entry.get("type") == report_type:
            path = REPORTS_ROOT / entry["relative_path"]
            if not path.is_file():
                _log.error("report missing on disk sid=%s type=%s path=%s",
                           webapp_submission_id, report_type, path)
                raise HTTPException(500, "report file missing on disk")
            _log.info("stream report sid=%s user=%s type=%s trace=%s",
                      webapp_submission_id, user_id, report_type, row.get("trace_id"))
            return FileResponse(
                str(path),
                media_type="application/pdf",
                filename=f"{webapp_submission_id}-{report_type}.pdf",
            )
    raise HTTPException(404, f"report type {report_type} not present in manifest")


# ----------------------------- GET /submissions (reconciliation) -----------------------------

@app.get("/submissions")
def list_submissions(
    state: str = Query(...),
    updated_since: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    x_pipeline_service_token: Optional[str] = Header(None, alias="X-Pipeline-Service-Token"),
) -> dict:
    _require_service_token(x_pipeline_service_token)
    rows = db.list_by_state(state, updated_since=updated_since, limit=limit)
    for r in rows:
        r.pop("idempotency_key", None)
    return {"count": len(rows), "submissions": rows}


# ----------------------------- GET /submissions/{id}/raw-export -----------------------------

@app.get("/submissions/{webapp_submission_id}/raw-export")
def get_raw_export(
    webapp_submission_id: str,
    user_id: str = Query(...),
    x_pipeline_service_token: Optional[str] = Header(None, alias="X-Pipeline-Service-Token"),
):
    """Return the sanitized evidence archive as a tar.gz stream.

    Replaces the prior webapp-side SSH path. Uses the same service-token
    auth as every other endpoint. Runs sanitize_for_export.py on the
    pipeline VM (where the analyses dir lives), packs the sanitized
    artifacts, returns the tar.gz. Streaming is buffered in memory —
    archives for typical samples are 50 KB to 5 MB.
    """
    _require_service_token(x_pipeline_service_token)
    row = db.get_for_user(webapp_submission_id, user_id)
    if row is None:
        raise HTTPException(404, "not found or not authorized")

    state = row["state"]
    if state != "complete":
        if state.startswith("failed_"):
            raise HTTPException(410, f"analysis failed: {row.get('error_code') or state}")
        raise HTTPException(409, f"analysis not complete; state={state}")

    task_id = row.get("cuckoo_task_id")
    if not task_id:
        raise HTTPException(500, "no cuckoo_task_id on submission row")

    analyses_dir = Path(f"/opt/pipeline/data/analyses/{task_id}")
    if not analyses_dir.is_dir():
        raise HTTPException(
            410,
            "analysis directory has been purged; archive is no longer available",
        )

    task_dirs = sorted(
        d for d in analyses_dir.iterdir()
        if d.is_dir() and d.name.startswith("task_")
    )
    if not task_dirs:
        raise HTTPException(500, "no task_N directory in analysis")

    # Run the on-demand sanitizer. Task_id is passed positionally; the
    # script writes _pipeline/{setup_overview.md, *_sanitized.*, ...} in
    # place. Idempotent — safe to call every download.
    try:
        result = subprocess.run(
            [sys.executable, "-m", "app.sanitize_for_export", task_id],
            cwd="/opt/pipeline",
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        _log.error("sanitize_for_export timeout task=%s sid=%s", task_id, webapp_submission_id)
        raise HTTPException(504, "sanitize step timed out")
    if result.returncode != 0:
        _log.error(
            "sanitize_for_export failed task=%s sid=%s rc=%d stderr=%s",
            task_id, webapp_submission_id, result.returncode,
            result.stderr.decode(errors="replace")[:500],
        )
        raise HTTPException(500, "sanitize step failed")

    pipeline_dir = analyses_dir / "_pipeline"

    # Files to include in the archive. Fallback chain for bundle name —
    # whichever exists wins. Never error on a missing file; the archive
    # just carries what is present.
    tar_targets: list[tuple[Path, str]] = [
        (pipeline_dir / "setup_overview.md",              "_pipeline/setup_overview.md"),
        (pipeline_dir / "sanitized_bundle_export.json",    "_pipeline/sanitized_bundle_export.json"),
        (pipeline_dir / "sanitized_bundle.json",           "_pipeline/sanitized_bundle.json"),
        (pipeline_dir / "sanitization_manifest.json",      "_pipeline/sanitization_manifest.json"),
        (pipeline_dir / "agent_analysis_sanitized.json",   "_pipeline/agent_analysis_sanitized.json"),
        (pipeline_dir / "payload_log_sanitized.txt",       "_pipeline/payload_log_sanitized.txt"),
    ]

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        added: set[str] = set()
        for src, arcname in tar_targets:
            if not src.is_file() or arcname in added:
                continue
            tar.add(str(src), arcname=arcname)
            added.add(arcname)
        # Screenshots as-is (documented as unredacted)
        shots_dir = task_dirs[0] / "screenshots"
        if shots_dir.is_dir():
            for shot in sorted(shots_dir.iterdir()):
                if shot.is_file():
                    tar.add(
                        str(shot),
                        arcname=f"{task_dirs[0].name}/screenshots/{shot.name}",
                    )

    payload = buf.getvalue()
    _log.info(
        "raw-export sid=%s task=%s user=%s bytes=%d files=%d",
        webapp_submission_id, task_id, user_id, len(payload), len(added),
    )
    return Response(
        content=payload,
        media_type="application/gzip",
        headers={
            "Content-Disposition":
                f'attachment; filename="{webapp_submission_id}-raw-export.tar.gz"',
        },
    )




# ----------------------------- GET /health -----------------------------

@app.get("/health")
def health() -> dict:
    ollama_ok = False
    try:
        import httpx
        r = httpx.get("http://127.0.0.1:11434/api/version", timeout=2.0)
        ollama_ok = r.status_code == 200
    except Exception:
        pass

    chroma_ok = False
    chroma_count = 0
    try:
        from app.knowledge import get_collection
        col = get_collection()
        chroma_count = col.count()
        chroma_ok = chroma_count > 0
    except Exception:
        pass

    db_ok = False
    try:
        db.get("00000000-0000-4000-8000-000000000000")
        db_ok = True
    except Exception:
        pass

    return {
        "ok": ollama_ok and chroma_ok and db_ok,
        "ollama": ollama_ok,
        "chroma": chroma_ok,
        "chroma_chunk_count": chroma_count,
        "database": db_ok,
        "checked_at": _now(),
    }



# ----------------------------- GET /workers/health -----------------------------

@app.get("/workers/health")
def workers_health() -> dict:
    """Report which pipeline worker slots are alive via their flock files.

    A worker holds an exclusive flock on data/worker-<id>.lock for its
    process lifetime. If we can acquire it, the worker is dead. If we
    cannot, the worker is alive. Same liveness probe as worker.py's
    _worker_alive(), which _reclaim_zombies uses to decide whether a
    stuck submission can be reclaimed.
    """
    import fcntl

    def _alive(wid: str) -> bool:
        lock_path = Path(f"/opt/pipeline/data/worker-{wid}.lock")
        try:
            fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            return False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
                return False
            except BlockingIOError:
                return True
        finally:
            os.close(fd)

    states = {str(i): _alive(str(i)) for i in range(1, 10)}
    alive = sum(1 for v in states.values() if v)
    return {"ok": alive > 0, "alive": alive, "workers": states,
            "checked_at": _now()}


# ----------------------------- GET /queue -----------------------------

@app.get("/queue")
def queue_state() -> dict:
    """Current submission queue depth and active count.

    Used by the webapp to show users their queue position and an ETA.
    `parallel_slots` mirrors OLLAMA_NUM_PARALLEL so the webapp can compute
    realistic wait estimates without a second config source.
    """
    with db._conn() as conn:
        pending = conn.execute(
            "SELECT COUNT(*) FROM submissions "
            "WHERE state IN ('received', 'submitted_to_cuckoo')"
        ).fetchone()[0]
        active = conn.execute(
            "SELECT COUNT(*) FROM submissions "
            "WHERE state IN ('sandbox_running', 'sandbox_complete', "
            "'evidence_extracted', 'sanitized', 'retrieval_done', "
            "'generating_reports', 'verifying', 'rendering')"
        ).fetchone()[0]
    parallel_slots = int(os.environ.get("OLLAMA_NUM_PARALLEL", "2"))
    return {"pending": pending, "active": active,
            "parallel_slots": parallel_slots, "checked_at": _now()}




# ----------------------------- GET /knowledge/status -----------------------------

DASHBOARD_CACHE = Path("/opt/pipeline/data/.dashboard_snapshot.json")
DASHBOARD_CACHE_TTL_S = 3600


def _parse_tech_text(doc: str) -> tuple[str, str]:
    """Extract Mitigation / Detection blocks that ingest.py embeds in the doc."""
    mit = det = ""
    if " Mitigations: " in doc:
        tail = doc.split(" Mitigations: ", 1)[1]
        mit = tail.split(" | ")[0][:400]
    if " Detection: " in doc:
        seg = doc.split(" Detection: ", 1)[1]
        det = seg.split(" Mitigations: ", 1)[0][:400]
    return mit, det


def _build_dashboard_snapshot() -> dict:
    import time as _t
    from app.knowledge import get_collection
    col = get_collection()
    now_ts = int(_t.time())
    day = 86400

    def _rows(where):
        r = col.get(where=where, include=["metadatas", "documents"])
        return list(zip(
            r.get("ids", []),
            r.get("metadatas", []),
            r.get("documents", [""] * len(r.get("ids", []))),
        ))

    techniques = []
    for cid, meta, doc in _rows({"source_type": {"$eq": "mitre-attack"}}):
        mit, det = _parse_tech_text(doc if isinstance(doc, str) else "")
        techniques.append({
            "id": meta.get("technique_id", ""),
            "title": meta.get("title", ""),
            "tactics": json.loads(meta.get("tactics_json", "[]") or "[]"),
            "modified_ts": meta.get("modified_ts", 0),
            "mitigation": mit,
            "detection": det,
        })

    cves_all = []
    for cid, meta, _doc in _rows({"source_type": {"$in": ["nvd-cve", "cisa-kev"]}}):
        cvss = float(meta.get("cvss_score", 0) or 0)
        epss = float(meta.get("epss_score", 0) or 0)
        kev = bool(meta.get("kev", False))
        rans = (meta.get("kev_ransomware", "") or "").lower() in ("known", "true")
        base = 0.35 * (cvss / 10.0) + 0.40 * epss + (0.15 if kev else 0) + (0.10 if rans else 0)
        _cve_id = cid.replace("nvd:", "")
        _d = _doc if isinstance(_doc, str) else ""
        if _d.startswith(_cve_id + ": "):
            _d = _d[len(_cve_id) + 2:]
        _d = _d.split(" CVSS ")[0].split(" CWE: ")[0].strip()[:300]
        cves_all.append({
            "cve": _cve_id,
            "description": _d,
            "cvss": cvss,
            "epss": epss,
            "epss_pct": float(meta.get("epss_percentile", 0) or 0),
            "severity": meta.get("severity", ""),
            "cwe": json.loads(meta.get("cwe_ids_json", "[]") or "[]"),
            "kev": kev,
            "kev_ransomware": rans,
            "kev_due": meta.get("kev_due_date", ""),
            "published_ts": meta.get("published_ts", 0),
            "references": json.loads(meta.get("references_json", "[]") or "[]"),
            "base_score": round(base, 4),
        })

    cves_all.sort(key=lambda x: -x["base_score"])
    cves_top = cves_all[:2000]
    _recent_cut = now_ts - 14 * day
    recent_cves = sorted(
        [c for c in cves_all if c.get("published_ts", 0) >= _recent_cut],
        key=lambda x: -x.get("published_ts", 0),
    )[:150]

    cwe_counts: dict[str, int] = {}
    for c in cves_top:
        for w in c["cwe"]:
            cwe_counts[w] = cwe_counts.get(w, 0) + 1
    cwe_top = [{"cwe": k, "count": v}
               for k, v in sorted(cwe_counts.items(), key=lambda x: -x[1])[:20]]

    playbooks = []
    for cid, meta, doc in _rows({"source_type": {"$in": [
        "baseline-playbook", "baseline-nist", "baseline-owasp",
        "baseline-cwe", "baseline-capec",
    ]}}):
        playbooks.append({
            "id": meta.get("playbook_id") or cid,
            "title": meta.get("title", ""),
            "source_type": meta.get("source_type", ""),
            "preview": (doc[:280] if isinstance(doc, str) else ""),
        })


    import re as _re2
    cwe_remediation = {}
    for pb in playbooks:
        _t = (pb.get("title", "") or "") + " " + (pb.get("preview", "") or "")
        for _m in _re2.findall(r'CWE-(\d+)', _t):
            _key = f"CWE-{_m}"
            if _key not in cwe_remediation:
                cwe_remediation[_key] = {
                    "title": pb.get("title", ""),
                    "text": pb.get("preview", ""),
                    "source": pb.get("source_type", ""),
                }

    news = []
    for cid, meta, doc in _rows({"source_type": {"$in": ["security-news", "cisa-advisory", "vendor-advisory"]}}):
        pub = meta.get("published_ts", 0) or 0
        if pub and now_ts - pub > 14 * day:
            continue
        news.append({
            "title": meta.get("title", ""),
            "preview": (doc[:280] if isinstance(doc, str) else ""),
            "published_ts": pub,
            "feed": meta.get("feed_name", ""),
            "url": meta.get("source_url", ""),
        })
    news.sort(key=lambda x: -x["published_ts"])
    news = news[:60]

    return {
        "generated_ts": now_ts,
        "generated_at": _now(),
        "stats": {
            "techniques": len(techniques),
            "cves_loaded": len(cves_all),
            "playbooks": len(playbooks),
        },
        "techniques": techniques,
        "cves_top": cves_top,
        "recent_cves": recent_cves,
        "cwe_top": cwe_top,
        "playbooks": playbooks[:150],
        "cwe_remediation": cwe_remediation,
        "news": news,
    }


@app.get("/knowledge/dashboard_snapshot")
def dashboard_snapshot(
    x_pipeline_service_token: Optional[str] = Header(None, alias="X-Pipeline-Service-Token"),
) -> dict:
    _require_service_token(x_pipeline_service_token)
    import time as _t
    if DASHBOARD_CACHE.is_file() and (_t.time() - DASHBOARD_CACHE.stat().st_mtime) < DASHBOARD_CACHE_TTL_S:
        return json.loads(DASHBOARD_CACHE.read_text())
    snap = _build_dashboard_snapshot()
    DASHBOARD_CACHE.write_text(json.dumps(snap))
    return snap


@app.get("/knowledge/status")
def knowledge_status(
    x_pipeline_service_token: Optional[str] = Header(None, alias="X-Pipeline-Service-Token"),
) -> dict:
    _require_service_token(x_pipeline_service_token)
    from app.knowledge import get_collection
    col = get_collection()
    total = col.count()
    by_type: dict[str, int] = {}
    for st in ("mitre-attack", "baseline-playbook", "baseline-nist",
               "baseline-owasp", "baseline-cwe", "baseline-capec",
               "nvd-cve", "cisa-kev"):
        try:
            ids = col.get(where={"source_type": {"$eq": st}}, include=[])["ids"]
            by_type[st] = len(ids)
        except Exception:
            by_type[st] = 0
    return {"total": total, "by_type": by_type, "checked_at": _now()}
