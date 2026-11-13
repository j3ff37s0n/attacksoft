#!/usr/bin/env python3
"""Webapp cleanup job. Runs periodically via systemd timer."""
import logging
import sys
import traceback
from datetime import datetime, timezone, timedelta
from app import db, pipeline_reconcile

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("cleanup")

def run_cleanup():
    log.info("Starting webapp cleanup sweep")
    now = datetime.now(timezone.utc)

    # 0. Reconcile: poll pipeline for every non-terminal submission.
    #    Successful poll → state updated and TTL extended (pipeline is alive).
    #    Failed poll → row untouched (let TTL expiry handle it later).
    try:
        pending = db.get_stale_pending(older_than_seconds=60)
        reconciled = 0
        for sub in pending:
            user_id = db.pipeline_user_id_for(sub["client_id"])
            new_state = pipeline_reconcile.reconcile_submission(
                sub["webapp_submission_id"], user_id
            )
            if new_state is not None:
                reconciled += 1
        log.info(
            "Reconciliation: %d/%d pending submissions confirmed alive",
            reconciled, len(pending),
        )
    except Exception as e:
        log.error("Reconciliation error: %s", e)
        log.error(traceback.format_exc())

    # 0a. Worker health: if pipeline reports 0 workers alive, fail all
    # non-terminal submissions immediately (2 min worst case instead of
    # waiting for the state-change timeout below).
    try:
        with httpx.Client(timeout=5.0) as http:
            r = http.get(f"{PIPELINE_URL}/workers/health")
        if r.status_code == 200 and not r.json().get("ok"):
            with db._conn() as conn:
                rows = conn.execute(
                    "SELECT webapp_submission_id FROM submissions_cache "
                    "WHERE pipeline_state IN "
                    "('queued','analyzing','generating_reports')"
                ).fetchall()
            for row in rows:
                db.update_submission_state(
                    row["webapp_submission_id"], "failed",
                    error_code="pipeline_workers_dead",
                )
            if rows:
                log.info(
                    "Marked %d submissions failed: 0 workers alive",
                    len(rows),
                )
    except Exception as e:
        log.warning(f"Worker health check failed: {e}")

    # 0b. Stall detection: mark submissions failed if they haven't changed state
    # within the per-state budget. Catches dead workers (systemd 'failed'),
    # wedged workers (SIGSTOP, deadlock), and API-down cases.
    try:
        STALL_TIMEOUTS = {
            "queued":              30 * 60,
            "analyzing":           180 * 60,
            "generating_reports":  360 * 60,
        }
        stalled = 0
        for webapp_state, timeout_s in STALL_TIMEOUTS.items():
            cutoff = (now - timedelta(seconds=timeout_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
            with db._conn() as conn:
                rows = conn.execute(
                    "SELECT webapp_submission_id, last_state_change_at "
                    "FROM submissions_cache "
                    "WHERE pipeline_state = ? "
                    "  AND last_state_change_at IS NOT NULL "
                    "  AND last_state_change_at < ?",
                    (webapp_state, cutoff),
                ).fetchall()
            for row in rows:
                sid = row["webapp_submission_id"]
                db.update_submission_state(
                    sid, "failed", error_code="pipeline_stalled",
                )
                stalled += 1
                log.warning(
                    "Marked stalled submission %s failed "
                    "(state=%s unchanged since %s, >%d min)",
                    sid, webapp_state, row["last_state_change_at"],
                    timeout_s // 60,
                )
        if stalled:
            log.info("Stall sweep marked %d submissions failed", stalled)
    except Exception as e:
        log.error(f"Stall detection error: {e}")
        log.error(traceback.format_exc())

    # 1. Clean up expired submissions (normal 90-minute TTL)
    try:
        expired_subs = db.get_expired_submissions()
        if expired_subs:
            for sub in expired_subs:
                sid = sub["webapp_submission_id"]
                if sub["pipeline_state"] not in ("complete", "failed"):
                    db.update_submission_state(
                        sid, "failed", error_code="pipeline_timeout",
                    )
                    log.info(f"Marked stale submission failed: {sid}")
                else:
                    db.delete_submission(sid)
                    log.info(f"Deleted expired submission {sid}")
        else:
            log.info("No expired submissions found")
    except Exception as e:
        log.error(f"Expired submission cleanup error: {e}")
        log.error(traceback.format_exc())

    # 2. Clean up stale submissions (stuck in a non-terminal state for > 45 minutes)
    try:
        stale_cutoff = (now - timedelta(minutes=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows = []
        with db._conn() as conn:
            rows = conn.execute(
                "SELECT webapp_submission_id FROM submissions_cache "
                "WHERE pipeline_state NOT IN ('complete', 'failed') "
                "AND updated_at < ?",
                (stale_cutoff,)
            ).fetchall()

        if rows:
            for row in rows:
                sid = row[0]
                db.delete_submission(sid)
                log.info(f"Deleted stale submission {sid} (stuck >120 min)")
        else:
            log.info("No stale submissions found")
    except Exception as e:
        log.error(f"Stale submission cleanup error: {e}")
        log.error(traceback.format_exc())

    # 3. Daily purge: Remove any submission older than 24 hours (clears recent list)
    try:
        daily_cutoff = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows = []
        with db._conn() as conn:
            rows = conn.execute(
                "SELECT webapp_submission_id FROM submissions_cache WHERE created_at < ?",
                (daily_cutoff,)
            ).fetchall()
        
        if rows:
            for row in rows:
                sid = row[0]
                db.delete_submission(sid)
                log.info(f"Deleted old submission {sid} (older than 24h)")
        else:
            log.info("No old submissions found to purge")
    except Exception as e:
        log.error(f"Daily purge error: {e}")
        log.error(traceback.format_exc())

    # 4. Clean up expired clients
    try:
        expired_clients = db.get_expired_clients()
        if expired_clients:
            for client in expired_clients:
                cid = client["id"]
                db.delete_client(cid)
                log.info(f"Deleted expired client {cid}")
        else:
            log.info("No expired clients found")
    except Exception as e:
        log.error(f"Client cleanup error: {e}")
        log.error(traceback.format_exc())

    log.info("Cleanup sweep complete")

if __name__ == "__main__":
    run_cleanup()
