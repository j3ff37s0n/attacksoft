"""Submission database: SQLite state for every submission.

Owns the submissions table, the claim mechanism for multi-worker safety, and
retention. The DB is the single source of truth for state, report paths, and
retention. PDFs live on disk under data/reports/.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DB_PATH = Path("/opt/pipeline/data/pipeline.db")
REPORTS_ROOT = Path("/opt/pipeline/data/reports")
SCHEMA_VERSION = "submission-db-row/1.0"
PRAGMA_USER_VERSION = 3
RETENTION_DAYS = 365
BUSY_TIMEOUT_MS = 5000
CLAIM_TTL_SECONDS = 3600

VALID_STATES = {
    "received", "submitted_to_cuckoo", "sandbox_running", "sandbox_complete",
    "evidence_extracted", "sanitized", "retrieval_done", "generating_reports",
    "verifying", "rendering", "complete",
    "failed_cuckoo_api", "failed_extraction", "failed_sanitization",
    "failed_retrieval", "failed_generation", "failed_verification",
    "failed_rendering", "failed_callback", "failed_unknown",
}

TERMINAL_STATES = {
    "complete", "failed_cuckoo_api", "failed_extraction", "failed_sanitization",
    "failed_retrieval", "failed_generation", "failed_verification",
    "failed_rendering", "failed_callback", "failed_unknown",
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utcdate_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _retention_date(days: int = RETENTION_DAYS) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d")


def compute_user_hash(user_id: str) -> str:
    return hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:12]


def _conn(db_path: Path | None = None, isolation_level: str | None = "") -> sqlite3.Connection:
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(path),
        timeout=BUSY_TIMEOUT_MS / 1000,
        isolation_level=isolation_level,
    )
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init(db_path: Path | None = None) -> None:
    with _conn(db_path) as conn:
        # Step 1: create the table if it does not exist. On a fresh DB this
        # creates all columns including worker_claim / worker_claim_at.
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS submissions (
              webapp_submission_id TEXT PRIMARY KEY,
              pipeline_submission_id TEXT NOT NULL UNIQUE,
              user_id TEXT NOT NULL,
              user_id_sha256_12 TEXT NOT NULL,
              idempotency_key TEXT NOT NULL UNIQUE,
              callback_url TEXT NOT NULL,
              cuckoo_task_id TEXT,
              state TEXT NOT NULL CHECK (state IN (
                'received','submitted_to_cuckoo','sandbox_running','sandbox_complete',
                'evidence_extracted','sanitized','retrieval_done','generating_reports',
                'verifying','rendering','complete','failed_cuckoo_api','failed_extraction',
                'failed_sanitization','failed_retrieval','failed_generation',
                'failed_verification','failed_rendering','failed_callback','failed_unknown'
              )),
              error_code TEXT,
              trace_id TEXT NOT NULL,
              artifact_root TEXT NOT NULL,
              analysis_date TEXT NOT NULL CHECK (analysis_date GLOB '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]'),
              report_manifest_json TEXT NOT NULL DEFAULT '[]',
              sanitization_manifest_sha256 TEXT,
              retrieval_result_sha256 TEXT,
              llm_model TEXT,
              prompt_versions_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              submitted_at TEXT,
              sandbox_started_at TEXT,
              sandbox_completed_at TEXT,
              analysis_completed_at TEXT,
              retention_delete_after TEXT NOT NULL,
              worker_claim TEXT,
              worker_claim_at TEXT,
              requested_platform TEXT
            );
            """
        )

        # Step 2: migrate any pre-existing table that lacks the new columns.
        # Runs BEFORE any index that references those columns.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(submissions)").fetchall()}
        if "worker_claim" not in cols:
            conn.execute("ALTER TABLE submissions ADD COLUMN worker_claim TEXT")
        if "worker_claim_at" not in cols:
            conn.execute("ALTER TABLE submissions ADD COLUMN worker_claim_at TEXT")
        if "requested_platform" not in cols:
            conn.execute("ALTER TABLE submissions ADD COLUMN requested_platform TEXT")

        # Step 3: create indexes now that all columns exist.
        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_submissions_user_created
              ON submissions(user_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_submissions_state_updated
              ON submissions(state, updated_at);
            CREATE INDEX IF NOT EXISTS idx_submissions_task
              ON submissions(cuckoo_task_id);
            CREATE INDEX IF NOT EXISTS idx_submissions_retention
              ON submissions(retention_delete_after);
            CREATE INDEX IF NOT EXISTS idx_submissions_state_claim
              ON submissions(state, worker_claim, worker_claim_at);
            """
        )
        conn.execute(f"PRAGMA user_version = {PRAGMA_USER_VERSION}")
        conn.commit()


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["report_manifest_json"] = json.loads(d.get("report_manifest_json") or "[]")
    except Exception:
        d["report_manifest_json"] = []
    try:
        d["prompt_versions_json"] = json.loads(d.get("prompt_versions_json") or "{}")
    except Exception:
        d["prompt_versions_json"] = {}
    d["schema_version"] = SCHEMA_VERSION
    return d


# ----------------------------- writes -----------------------------

def insert_or_get(
    webapp_submission_id: str,
    pipeline_submission_id: str,
    user_id: str,
    idempotency_key: str,
    callback_url: str,
    artifact_root: str,
    analysis_date: str,
    trace_id: str,
    state: str = "received",
    requested_platform: str | None = None,
    db_path: Path | None = None,
) -> tuple[dict, bool]:
    if state not in VALID_STATES:
        raise ValueError(f"invalid state: {state}")
    if not analysis_date or len(analysis_date) != 8 or not analysis_date.isdigit():
        raise ValueError(f"analysis_date must be YYYYMMDD: {analysis_date!r}")

    now = _utcnow()
    user_hash = compute_user_hash(user_id)
    retention = _retention_date()

    with _conn(db_path) as conn:
        existing = conn.execute(
            "SELECT * FROM submissions WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if existing is not None:
            if existing["user_id"] != user_id or existing["webapp_submission_id"] != webapp_submission_id:
                raise ValueError(
                    "idempotency_key collision with different user or submission id: "
                    f"existing={existing['webapp_submission_id']} requested={webapp_submission_id}"
                )
            return _row_to_dict(existing), False

        conn.execute(
            """
            INSERT INTO submissions (
              webapp_submission_id, pipeline_submission_id, user_id,
              user_id_sha256_12, idempotency_key, callback_url, state,
              trace_id, artifact_root, analysis_date, created_at, updated_at,
              retention_delete_after, requested_platform
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                webapp_submission_id, pipeline_submission_id, user_id,
                user_hash, idempotency_key, callback_url, state,
                trace_id, artifact_root, analysis_date, now, now, retention,
                requested_platform,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM submissions WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        ).fetchone()
    return _row_to_dict(row), True


def claim_one(
    state: str,
    worker_id: str,
    ttl_seconds: int = CLAIM_TTL_SECONDS,
    db_path: Path | None = None,
) -> dict | None:
    """Atomically claim one unclaimed row in the given state.

    Returns the claimed row, or None if no unclaimed row exists.
    A claim older than ttl_seconds is considered stale and may be re-claimed.
    """
    if state not in VALID_STATES:
        raise ValueError(f"invalid state: {state}")
    now = _utcnow()
    cutoff = (
        datetime.now(timezone.utc) - timedelta(seconds=ttl_seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    path = db_path or DB_PATH
    conn = _conn(db_path, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT webapp_submission_id FROM submissions "
            "WHERE state = ? AND (worker_claim IS NULL OR worker_claim_at < ?) "
            "ORDER BY created_at ASC LIMIT 1",
            (state, cutoff),
        ).fetchone()
        if row is None:
            conn.execute("COMMIT")
            return None
        sid = row["webapp_submission_id"]
        cur = conn.execute(
            "UPDATE submissions SET worker_claim = ?, worker_claim_at = ?, updated_at = ? "
            "WHERE webapp_submission_id = ? AND state = ? "
            "  AND (worker_claim IS NULL OR worker_claim_at < ?)",
            (worker_id, now, now, sid, state, cutoff),
        )
        if cur.rowcount == 0:
            conn.execute("COMMIT")
            return None
        conn.execute("COMMIT")
        final = conn.execute(
            "SELECT * FROM submissions WHERE webapp_submission_id = ?",
            (sid,),
        ).fetchone()
        return _row_to_dict(final) if final else None
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


def release_claim(
    webapp_submission_id: str,
    worker_id: str,
    db_path: Path | None = None,
) -> None:
    """Release a claim. Safe to call even if the claim was already superseded."""
    with _conn(db_path) as conn:
        conn.execute(
            "UPDATE submissions SET worker_claim = NULL, worker_claim_at = NULL "
            "WHERE webapp_submission_id = ? AND worker_claim = ?",
            (webapp_submission_id, worker_id),
        )
        conn.commit()

def reclaim_zombie(
    webapp_submission_id: str,
    timeout_states: tuple[str, ...] = ("generating_reports", "verifying", "rendering"),
    db_path: Path | None = None,
) -> bool:
    """Atomically move a stuck tail-state row back to retrieval_done.

    Called by worker._reclaim_zombies() after the row's updated_at exceeds
    ZOMBIE_TIMEOUT_S. Clears the worker claim so any worker can re-pick it up.
    Returns True if a row was reclaimed, False if a race already moved it.
    """
    now = _utcnow()
    placeholders = ",".join("?" * len(timeout_states))
    with _conn(db_path) as conn:
        cur = conn.execute(
            f"UPDATE submissions SET state='retrieval_done', worker_claim=NULL, "
            f"worker_claim_at=NULL, updated_at=? "
            f"WHERE webapp_submission_id=? AND state IN ({placeholders})",
            [now, webapp_submission_id, *timeout_states],
        )
        conn.commit()
        return cur.rowcount > 0


def renew_claim(sid: str, worker_id: str) -> bool:
    """Extend the claim lease while a worker is actively processing.

    Called from the generation heartbeat so worker_claim_at never goes
    stale during long-running _generate_all_reports_v2 calls. Without
    this, CLAIM_TTL_SECONDS (1 hour) expires mid-generation and other
    workers re-claim the same row, causing duplicate concurrent work.
    """
    now = _now()
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE submissions SET worker_claim_at = ?, updated_at = ? "
            "WHERE webapp_submission_id = ? AND worker_claim = ?",
            (now, now, sid, worker_id),
        )
        conn.commit()
        return cur.rowcount > 0


def touch_submission(sid: str) -> None:
    """Bump updated_at without changing state. Used by the worker
    heartbeat so _reclaim_zombies does not treat a live-but-slow
    submission as a dead worker."""
    now = _now()
    with _conn() as conn:
        conn.execute(
            "UPDATE submissions SET updated_at = ? WHERE webapp_submission_id = ?",
            (now, sid),
        )
        conn.commit()


def set_state(
    webapp_submission_id: str,
    state: str,
    error_code: str | None = None,
    db_path: Path | None = None,
    **extra_fields: Any,
) -> dict:
    if state not in VALID_STATES:
        raise ValueError(f"invalid state: {state}")
    if state.startswith("failed_") and not error_code:
        raise ValueError(f"state {state} requires error_code")
    if error_code is not None and not state.startswith("failed_"):
        raise ValueError(f"error_code set but state {state} is not a failure state")

    allowed_extra = {
        "cuckoo_task_id", "analysis_date", "artifact_root",
        "submitted_at", "sandbox_started_at", "sandbox_completed_at",
        "analysis_completed_at",
    }
    bad = set(extra_fields) - allowed_extra
    if bad:
        raise ValueError(f"unknown extra fields: {bad}")

    now = _utcnow()
    with _conn(db_path) as conn:
        current = conn.execute(
            "SELECT state FROM submissions WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        ).fetchone()
        if current is None:
            raise ValueError(f"submission not found: {webapp_submission_id}")
        current_state = current["state"]
        if current_state in TERMINAL_STATES and state != current_state:
            raise ValueError(
                f"cannot transition from terminal state {current_state} to {state} "
                f"for {webapp_submission_id}"
            )
        set_clauses = ["state = ?", "error_code = ?", "updated_at = ?"]
        values: list[Any] = [state, error_code, now]
        for k, v in extra_fields.items():
            set_clauses.append(f"{k} = ?")
            values.append(v)
        values.append(webapp_submission_id)
        conn.execute(
            f"UPDATE submissions SET {', '.join(set_clauses)} WHERE webapp_submission_id = ?",
            values,
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM submissions WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        ).fetchone()
    return _row_to_dict(row)


def set_task_path(
    webapp_submission_id: str,
    cuckoo_task_id: str,
    analysis_date: str,
    artifact_root: str,
    db_path: Path | None = None,
) -> dict:
    if not analysis_date or len(analysis_date) != 8 or not analysis_date.isdigit():
        raise ValueError(f"analysis_date must be YYYYMMDD: {analysis_date!r}")
    now = _utcnow()
    with _conn(db_path) as conn:
        current = conn.execute(
            "SELECT state FROM submissions WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        ).fetchone()
        if current is None:
            raise ValueError(f"submission not found: {webapp_submission_id}")
        if current["state"] in TERMINAL_STATES:
            raise ValueError(
                f"cannot set task path on terminal-state submission {webapp_submission_id}"
            )
        conn.execute(
            """
            UPDATE submissions
            SET cuckoo_task_id = ?,
                analysis_date = ?,
                artifact_root = ?,
                submitted_at = COALESCE(submitted_at, ?),
                state = CASE
                  WHEN state = 'received' THEN 'submitted_to_cuckoo'
                  ELSE state
                END,
                updated_at = ?
            WHERE webapp_submission_id = ?
            """,
            (cuckoo_task_id, analysis_date, artifact_root, now, now, webapp_submission_id),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM submissions WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        ).fetchone()
    return _row_to_dict(row)


def set_report_manifest(
    webapp_submission_id: str,
    manifest: list[dict],
    db_path: Path | None = None,
) -> dict:
    now = _utcnow()
    payload = json.dumps(manifest)
    with _conn(db_path) as conn:
        conn.execute(
            "UPDATE submissions SET report_manifest_json = ?, updated_at = ? "
            "WHERE webapp_submission_id = ?",
            (payload, now, webapp_submission_id),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM submissions WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        ).fetchone()
    if row is None:
        raise ValueError(f"submission not found: {webapp_submission_id}")
    return _row_to_dict(row)


def set_aux_metadata(
    webapp_submission_id: str,
    sanitization_manifest_sha256: str | None = None,
    retrieval_result_sha256: str | None = None,
    llm_model: str | None = None,
    prompt_versions: dict | None = None,
    db_path: Path | None = None,
) -> dict:
    fields = []
    values: list[Any] = []
    if sanitization_manifest_sha256 is not None:
        fields.append("sanitization_manifest_sha256 = ?")
        values.append(sanitization_manifest_sha256)
    if retrieval_result_sha256 is not None:
        fields.append("retrieval_result_sha256 = ?")
        values.append(retrieval_result_sha256)
    if llm_model is not None:
        fields.append("llm_model = ?")
        values.append(llm_model)
    if prompt_versions is not None:
        fields.append("prompt_versions_json = ?")
        values.append(json.dumps(prompt_versions))
    if not fields:
        raise ValueError("no fields to update")
    fields.append("updated_at = ?")
    values.append(_utcnow())
    values.append(webapp_submission_id)
    with _conn(db_path) as conn:
        conn.execute(
            f"UPDATE submissions SET {', '.join(fields)} WHERE webapp_submission_id = ?",
            values,
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM submissions WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        ).fetchone()
    if row is None:
        raise ValueError(f"submission not found: {webapp_submission_id}")
    return _row_to_dict(row)


# ----------------------------- reads -----------------------------

def get(webapp_submission_id: str, db_path: Path | None = None) -> dict | None:
    with _conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM submissions WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        ).fetchone()
    return _row_to_dict(row) if row else None


def get_for_user(
    webapp_submission_id: str,
    user_id: str,
    db_path: Path | None = None,
) -> dict | None:
    row = get(webapp_submission_id, db_path)
    if row is None:
        return None
    if row["user_id"] != user_id:
        log.warning(
            "idor_attempt submission=%s requested_user=%s actual_user=%s",
            webapp_submission_id, user_id, row["user_id"],
        )
        return None
    return row


def list_for_user(
    user_id: str,
    limit: int = 50,
    offset: int = 0,
    db_path: Path | None = None,
) -> list[dict]:
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM submissions WHERE user_id = ? "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user_id, limit, offset),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]

def list_all_task_ids(db_path: Path | None = None) -> list[str]:
    """Return every cuckoo_task_id in submissions, any state.

    Used by worker._orphan_sweep to decide which analyses/<task_id>/ dirs to
    preserve. A dir is preserved if its task_id has any DB row, because a
    completed row stays for 24h for the raw-export window; the webapp
    cleanup job deletes the row and the dir together when the window expires.
    """
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT DISTINCT cuckoo_task_id FROM submissions "
            "WHERE cuckoo_task_id IS NOT NULL"
        ).fetchall()
    return [r[0] for r in rows]


def list_by_state(
    state: str,
    updated_since: str | None = None,
    limit: int = 200,
    db_path: Path | None = None,
) -> list[dict]:
    query = "SELECT * FROM submissions WHERE state = ?"
    params: list[Any] = [state]
    if updated_since:
        query += " AND updated_at >= ?"
        params.append(updated_since)
    query += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)
    with _conn(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_dict(r) for r in rows]


# ----------------------------- retention -----------------------------

def _delete_pdf_files(manifest: list[dict], reports_root: Path) -> int:
    deleted = 0
    for entry in manifest:
        rel = entry.get("relative_path")
        if not rel:
            continue
        path = reports_root / rel
        try:
            if path.is_file():
                path.unlink()
                deleted += 1
        except Exception as exc:
            log.warning("pdf_delete_failed path=%s error=%s", path, exc)
    return deleted


def _delete_submission_dir(webapp_submission_id: str, reports_root: Path) -> bool:
    d = reports_root / webapp_submission_id
    if not d.is_dir():
        return False
    try:
        for f in d.iterdir():
            if f.is_file():
                f.unlink()
        d.rmdir()
        return True
    except Exception as exc:
        log.warning("dir_delete_failed path=%s error=%s", d, exc)
        return False


def apply_retention(
    now_date: str | None = None,
    dry_run: bool = False,
    reports_root: Path | None = None,
    db_path: Path | None = None,
    limit: int = 1000,
) -> dict:
    today = now_date or _utcdate_today()
    root = reports_root or REPORTS_ROOT
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT webapp_submission_id, report_manifest_json, state FROM submissions "
            "WHERE retention_delete_after < ? LIMIT ?",
            (today, limit),
        ).fetchall()

    to_delete = []
    for r in rows:
        if r["state"] not in TERMINAL_STATES:
            continue
        to_delete.append(dict(r))

    if dry_run:
        return {
            "dry_run": True,
            "would_delete": [r["webapp_submission_id"] for r in to_delete],
            "count": len(to_delete),
        }

    pdfs_deleted = 0
    dirs_deleted = 0
    rows_deleted = 0
    for r in to_delete:
        try:
            manifest = json.loads(r["report_manifest_json"] or "[]")
        except Exception:
            manifest = []
        pdfs_deleted += _delete_pdf_files(manifest, root)
        if _delete_submission_dir(r["webapp_submission_id"], root):
            dirs_deleted += 1
        with _conn(db_path) as conn:
            conn.execute(
                "DELETE FROM submissions WHERE webapp_submission_id = ?",
                (r["webapp_submission_id"],),
            )
            conn.commit()
        rows_deleted += 1

    if rows_deleted > 0:
        with _conn(db_path) as conn:
            conn.execute("PRAGMA optimize")
            conn.execute("VACUUM")
            conn.commit()

    return {
        "dry_run": False,
        "rows_deleted": rows_deleted,
        "pdfs_deleted": pdfs_deleted,
        "dirs_deleted": dirs_deleted,
        "as_of": today,
    }


# ----------------------------- smoke test -----------------------------

def _verify() -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        db = tmp_path / "test.db"
        reports = tmp_path / "reports"
        reports.mkdir()

        try:
            init(db)
        except Exception as exc:
            print(f"FAIL init: {exc}")
            return 1

        sid = str(uuid.uuid4())
        psid = str(uuid.uuid4())
        row, created = insert_or_get(
            webapp_submission_id=sid,
            pipeline_submission_id=psid,
            user_id="alice",
            idempotency_key="key-1",
            callback_url="http://10.10.10.1:8080/cb",
            artifact_root="20261030/TASK1",
            analysis_date="20261030",
            trace_id=str(uuid.uuid4()),
            db_path=db,
        )
        if not created:
            print("FAIL insert_or_get: expected created=True")
            failures += 1
        else:
            print("PASS insert_or_get created")

        row2, created2 = insert_or_get(
            webapp_submission_id=sid,
            pipeline_submission_id=psid,
            user_id="alice",
            idempotency_key="key-1",
            callback_url="http://10.10.10.1:8080/cb",
            artifact_root="20261030/TASK1",
            analysis_date="20261030",
            trace_id=row["trace_id"],
            db_path=db,
        )
        if created2 or row2["webapp_submission_id"] != sid:
            print("FAIL insert_or_get idempotency")
            failures += 1
        else:
            print("PASS insert_or_get idempotency")

        try:
            insert_or_get(
                webapp_submission_id=str(uuid.uuid4()),
                pipeline_submission_id=str(uuid.uuid4()),
                user_id="bob",
                idempotency_key="key-1",
                callback_url="http://10.10.10.1:8080/cb",
                artifact_root="20261030/TASK2",
                analysis_date="20261030",
                trace_id=str(uuid.uuid4()),
                db_path=db,
            )
            print("FAIL idempotency collision not detected")
            failures += 1
        except ValueError:
            print("PASS idempotency collision detected")

        for state in ("submitted_to_cuckoo", "sandbox_running", "sandbox_complete",
                      "evidence_extracted", "sanitized", "retrieval_done",
                      "generating_reports", "verifying", "rendering"):
            set_state(sid, state, db_path=db)
        set_state(sid, "complete", db_path=db)
        print("PASS forward transitions")

        try:
            set_state(sid, "failed_generation", error_code="x", db_path=db)
            print("FAIL terminal transition not blocked")
            failures += 1
        except ValueError:
            print("PASS terminal transition blocked")

        if get_for_user(sid, "bob", db_path=db) is not None:
            print("FAIL IDOR not blocked")
            failures += 1
        else:
            print("PASS IDOR blocked")
        if get_for_user(sid, "alice", db_path=db) is None:
            print("FAIL authorized get_for_user returned None")
            failures += 1
        else:
            print("PASS authorized get_for_user works")

        pdf_dir = reports / sid
        pdf_dir.mkdir(parents=True)
        (pdf_dir / "executive_risk.pdf").write_bytes(b"%PDF-1.4\n%test")
        manifest = [{
            "type": "executive_risk",
            "sha256": "0" * 64,
            "generated_at": "2026-10-30T00:00:00Z",
            "relative_path": f"{sid}/executive_risk.pdf",
        }]
        set_report_manifest(sid, manifest, db_path=db)

        sid2 = str(uuid.uuid4())
        psid2 = str(uuid.uuid4())
        insert_or_get(
            webapp_submission_id=sid2,
            pipeline_submission_id=psid2,
            user_id="alice",
            idempotency_key="key-2",
            callback_url="http://10.10.10.1:8080/cb",
            artifact_root="20261030/TASK3",
            analysis_date="20261030",
            trace_id=str(uuid.uuid4()),
            db_path=db,
        )

        claimed = claim_one("received", "worker-1", db_path=db)
        if claimed is None or claimed["webapp_submission_id"] != sid2:
            print("FAIL claim_one did not claim the row")
            failures += 1
        else:
            print("PASS claim_one claimed the row")
        claimed2 = claim_one("received", "worker-2", db_path=db)
        if claimed2 is not None:
            print("FAIL claim_one allowed double-claim")
            failures += 1
        else:
            print("PASS claim_one prevented double-claim")
        release_claim(sid2, "worker-1", db_path=db)
        reclaimed = claim_one("received", "worker-2", db_path=db)
        if reclaimed is None or reclaimed["webapp_submission_id"] != sid2:
            print("FAIL claim_one after release")
            failures += 1
        else:
            print("PASS claim_one after release")
        release_claim(sid2, "worker-2", db_path=db)

        set_state(sid2, "failed_extraction", error_code="extract_failed", db_path=db)

        with _conn(db) as conn:
            conn.execute(
                "UPDATE submissions SET retention_delete_after = '2020-01-01'"
            )
            conn.commit()

        result = apply_retention(
            now_date="2025-01-01",
            reports_root=reports,
            db_path=db,
        )
        if result["rows_deleted"] != 2:
            print(f"FAIL retention rows_deleted={result['rows_deleted']}")
            failures += 1
        elif result["pdfs_deleted"] != 1:
            print(f"FAIL retention pdfs_deleted={result['pdfs_deleted']}")
            failures += 1
        elif (pdf_dir / "executive_risk.pdf").exists():
            print("FAIL retention pdf still on disk")
            failures += 1
        elif get(sid, db_path=db) is not None:
            print("FAIL retention row still in DB")
            failures += 1
        else:
            print(f"PASS retention ({result['rows_deleted']} rows, {result['pdfs_deleted']} pdfs)")

    if failures:
        print(f"{failures} failure(s)")
        return 1
    print("all db checks passed")
    return 0
def list_terminal_past(cutoff_iso: str, db_path: Path | None = None) -> list[dict]:
    """Terminal-state rows past a cutoff. Used by pipeline purge sweep.

    Timestamp used for comparison: analysis_completed_at for `complete`,
    updated_at for failures. Both are set at terminal-state entry.
    """
    terminal = (
        "complete",
        "failed_cuckoo_api", "failed_extraction", "failed_sanitization",
        "failed_retrieval", "failed_generation", "failed_verification",
        "failed_rendering", "failed_callback", "failed_unknown",
    )
    placeholders = ",".join("?" * len(terminal))
    with _conn(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM submissions "
            f"WHERE state IN ({placeholders}) "
            f"  AND COALESCE(analysis_completed_at, updated_at) < ? "
            f"ORDER BY COALESCE(analysis_completed_at, updated_at) ASC "
            f"LIMIT 200",
            (*terminal, cutoff_iso),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def delete_submission(webapp_submission_id: str, db_path: Path | None = None) -> bool:
    """Delete a submission row. Used by pipeline purge sweep."""
    with _conn(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM submissions WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        )
        conn.commit()
        return cur.rowcount > 0


def main() -> int:
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if len(sys.argv) < 2:
        print("usage: python -m app.db init | verify | retention [--dry-run]", file=sys.stderr)
        return 2
    cmd = sys.argv[1]
    if cmd == "init":
        init()
        print(f"initialized {DB_PATH}")
        return 0
    if cmd == "verify":
        return _verify()
    if cmd == "retention":
        dry = "--dry-run" in sys.argv[2:]
        result = apply_retention(dry_run=dry)
        print(json.dumps(result, indent=2))
        return 0
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
