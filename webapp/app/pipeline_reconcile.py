"""Shared pipeline reconciliation for the webapp and cleanup job.

Polls the pipeline for a submission's current state and mirrors it into the
webapp cache. Called from the /s/<sid> detail route (user-triggered) and from
cleanup.py (periodic sweep) so TTL stays fresh while the pipeline is working.
"""
import logging
import os

import httpx

from app import db

log = logging.getLogger(__name__)

PIPELINE_URL = os.environ["PIPELINE_URL"].rstrip("/")
PIPELINE_SERVICE_TOKEN = os.environ["PIPELINE_SERVICE_TOKEN"]


def reconcile_submission(sid: str, user_id: str) -> str | None:
    """Poll pipeline for `sid`. Update local cache. Return new local state.

    Returns None if the pipeline is unreachable or returns non-200. Callers
    should treat None as "pipeline did not confirm liveness" — do not extend
    TTL on None.
    """
    try:
        with httpx.Client(timeout=10.0) as http:
            r = http.get(
                f"{PIPELINE_URL}/submissions/{sid}",
                headers={"X-Pipeline-Service-Token": PIPELINE_SERVICE_TOKEN},
                params={"user_id": user_id},
            )
    except httpx.HTTPError as e:
        log.debug("pipeline unreachable sid=%s: %s", sid, e)
        return None
    if r.status_code != 200:
        log.debug("pipeline returned %d sid=%s", r.status_code, sid)
        return None

    data = r.json()
    pl_state = data.get("state", "")

    if pl_state == "complete":
        db.update_submission_state(
            sid, "complete",
            report_manifest=data.get("report_manifest_json") or [],
        )
        return "complete"
    if pl_state.startswith("failed_"):
        db.update_submission_state(
            sid, "failed",
            error_code=data.get("error_code") or pl_state,
        )
        return "failed"
    if pl_state in ("retrieval_done", "generating_reports", "verifying", "rendering"):
        db.update_submission_state(sid, "generating_reports")
        return "generating_reports"
    # received, submitted_to_cuckoo, sandbox_running, sandbox_complete,
    # evidence_extracted, sanitized → "analyzing". The pipeline is alive and
    # working; TTL extends via update_submission_state.
    db.update_submission_state(sid, "analyzing")
    return "analyzing"
