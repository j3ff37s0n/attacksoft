"""Anonymous webapp: submission, status, PDF proxy, callback receiver.

No accounts. No login. Session cookie is signed with SECRET_KEY, contains a
random session token whose SHA-256 hash is the client identity in the
database. Client IP is hashed with IP_HASH_SECRET; plaintext IP never
persists.

Flow: user POSTs a file → webapp creates cache row 'queued' → forwards to
pipeline → pipeline returns 202 → webapp marks 'analyzing'. When the pipeline
finishes, it POSTs /api/callback which updates the cache to 'complete' or
'failed'. Between submission and callback, the detail page polls the pipeline
directly if the cache row is stale.

Reports proxy through this app so the pipeline URL is never exposed to the
browser.
"""
from __future__ import annotations

import os
import uuid
import subprocess
import logging
from datetime import datetime, timedelta, timezone


import httpx
from flask import (
    Flask, Response, abort, flash, jsonify, redirect, render_template,
    request, session, url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from app import db, dinosaurs, stripe_handler
from app.intel import intel_bp
log = logging.getLogger(__name__)

SECRET_KEY = os.environ["SECRET_KEY"]
IP_HASH_SECRET = os.environ["IP_HASH_SECRET"]
PIPELINE_URL = os.environ["PIPELINE_URL"].rstrip("/")
PIPELINE_SERVICE_TOKEN = os.environ["PIPELINE_SERVICE_TOKEN"]
PIPELINE_CALLBACK_URL = os.environ["PIPELINE_CALLBACK_URL"]
PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:8080").rstrip("/")

MAX_UPLOAD_BYTES = 200 * 1024 * 1024

# Generic user-facing status copy. Avoids pipeline-internal terminology
# (Cuckoo, LLM, sandbox analyzer, etc.) so that end users perceive the system
# as a black box that produces results.
STATUS_COPY = {
    "queued": "Preparing the observation chamber",
    "analyzing": "Sandbox extrapolation in progress",
    "generating_reports": "Compiling automated results",
    "complete": "Analysis sealed",
    "failed": "Extrapolation halted",
}
STATUS_SUB = {
    "queued": "Your file is being staged for review.",
    "analyzing": "The sample is being observed in a controlled environment.",
    "generating_reports": "Structured reports are being assembled from the observation.",
    "complete": "Your reports are ready below.",
    "failed": "The sample could not be fully observed. You may submit it again.",
}
ALLOWED_PLATFORMS = {"auto", "windows", "linux"}
REPORT_TYPES = ("executive_risk", "timeline_attack_chain", "remediation")
REFRESH_AFTER_SECONDS = 30

app = Flask(
    __name__,
    template_folder="/opt/webapp/templates",
    static_folder="/opt/webapp/static",
)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = PUBLIC_URL.startswith("https://")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=90)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + 1024

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.register_blueprint(intel_bp)

def client_ip() -> str:
    """Client IP through CF Tunnel → NPM → here.

    CF Tunnel sets CF-Connecting-IP; NPM may also set X-Forwarded-For. Falls
    back to the TCP peer address. On a LAN test with no proxy in front, this
    correctly returns the actual peer.
    """
    cf = request.headers.get("CF-Connecting-IP")
    if cf:
        return cf.strip()
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def ensure_client():
    """Return (client_row, ip_hash) for this request, creating if needed.

    Always touches the client row so last_seen_at and expires_at slide on
    activity — an active user stays alive past their first 90 min, an idle
    one ages out.
    """
    token = session.get("stoken")
    if not token:
        token = db.new_session_token()
        session["stoken"] = token
        session.permanent = True
    ip_hash = db.compute_ip_hash(client_ip(), IP_HASH_SECRET)
    return db.get_or_create_client(ip_hash, token), ip_hash


def _iso_seconds_remaining(iso_ts: str):
    try:
        exp = datetime.strptime(iso_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        delta = (exp - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(delta))
    except Exception:
        return None

def _refresh_from_pipeline(sub: dict, client_id: int) -> None:
    """If the cache row is non-terminal and stale, poll the pipeline once."""
    if sub["pipeline_state"] not in ("queued", "analyzing", "generating_reports"):
        return
    try:
        updated = datetime.strptime(
            sub["updated_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - updated < timedelta(seconds=REFRESH_AFTER_SECONDS):
            return
    except Exception:
        return
    from app.pipeline_reconcile import reconcile_submission
    reconcile_submission(
        sub["webapp_submission_id"],
        db.pipeline_user_id_for(client_id),
    )


def _queue_snapshot():
    """Call pipeline /queue. Returns {pending, active, parallel_slots} or None."""
    try:
        with httpx.Client(timeout=2.0) as http:
            r = http.get(f"{PIPELINE_URL}/queue")
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


@app.route("/healthz")
def healthz():
    checks: dict = {"self": True, "db": False, "pipeline": False}
    try:
        with db._conn() as conn:
            conn.execute("SELECT 1").fetchone()
        checks["db"] = True
    except Exception as e:
        checks["db_error"] = str(e)[:200]
    try:
        with httpx.Client(timeout=3.0) as http:
            r = http.get(f"{PIPELINE_URL}/health")
        if r.status_code == 200:
            checks["pipeline"] = bool(r.json().get("ok"))
    except Exception as e:
        checks["pipeline_error"] = str(e)[:200]
    ok = checks["db"] and checks["pipeline"]
    return jsonify({"ok": ok, **checks}), (200 if ok else 503)


@app.route("/")
def index():
    client, _ = ensure_client()
    submissions = db.list_submissions_for_client(client["id"], limit=20)
    return render_template(
        "index.html",
        submissions=submissions,
        max_upload_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
    )


@app.route("/submit", methods=["POST"])
def submit():
    client, ip_hash = ensure_client()

    # Origin/referer check for CSRF defense in depth (SameSite=Lax already
    # blocks cross-origin POST from a browser, but this catches edge cases).
    origin = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    if origin and not origin.startswith(PUBLIC_URL):
        abort(403, "bad origin")
    if not origin and referer and not referer.startswith(PUBLIC_URL):
        abort(403, "bad referer")

    file = request.files.get("file")
    if file is None or not file.filename:
        flash("Please choose a file to submit.")
        return redirect(url_for("index"))

    platform = (request.form.get("platform") or "auto").strip().lower()
    if platform not in ALLOWED_PLATFORMS:
        abort(400, "invalid platform")

    data = file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        abort(413, f"file exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    if not data:
        flash("Empty file.")
        return redirect(url_for("index"))

    filename = file.filename
    webapp_sid = str(uuid.uuid4())
    trace_id = str(uuid.uuid4())
    idempotency_key = str(uuid.uuid4())
    pipeline_uid = db.pipeline_user_id_for(client["id"])

    db.insert_submission_cache(
        webapp_submission_id=webapp_sid,
        client_id=client["id"],
        ip_hash=ip_hash,
        filename=filename,
        file_size=len(data),
        platform_requested=None if platform == "auto" else platform,
        trace_id=trace_id,
    )

    files = {"file": (filename, data, "application/octet-stream")}
    form = {
        "user_id": pipeline_uid,
        "webapp_submission_id": webapp_sid,
        "callback_url": PIPELINE_CALLBACK_URL,
        "trace_id": trace_id,
    }
    if platform != "auto":
        form["platform"] = platform
    headers = {
        "X-Pipeline-Service-Token": PIPELINE_SERVICE_TOKEN,
        "Idempotency-Key": idempotency_key,
    }
    try:
        with httpx.Client(timeout=30.0) as http:
            r = http.post(
                f"{PIPELINE_URL}/submissions",
                files=files, data=form, headers=headers,
            )
    except httpx.HTTPError as e:
        app.logger.error("pipeline submit network error: %s", e)
        db.update_submission_state(webapp_sid, "failed", error_code="pipeline_unreachable")
        return redirect(url_for("submission_detail", sid=webapp_sid))

    if r.status_code != 202:
        app.logger.error("pipeline submit %d: %s", r.status_code, r.text[:300])
        db.update_submission_state(
            webapp_sid, "failed",
            error_code=f"pipeline_{r.status_code}",
        )
        return redirect(url_for("submission_detail", sid=webapp_sid))

    db.update_submission_state(webapp_sid, "analyzing")
    return redirect(url_for("submission_detail", sid=webapp_sid))


@app.route("/s/<sid>")
def submission_detail(sid: str):
    client, _ = ensure_client()
    sub = db.get_submission_for_client(sid, client["id"])
    if sub is None:
        return render_template("expired.html"), 410
    _refresh_from_pipeline(sub, client["id"])
    # On return-from-checkout, verify the Stripe session directly so the user
    # sees the download immediately and does not have to wait for the webhook.
    if request.args.get("payment") == "success" and not sub["is_paid"]:
        session_id = request.args.get("session_id", "")
        if session_id and stripe_handler.verify_paid_session(session_id, sid):
            log.info("checkout verified inline sid=%s session=%s", sid, session_id)
    sub = db.get_submission_for_client(sid, client["id"])

    purchase_remaining = None
    if sub["pipeline_state"] == "complete":
        purchase_remaining = _iso_seconds_remaining(sub["expires_at"])

    dino_index, dino_flipped, dino_svg = dinosaurs.pick(sid)
    fleet = dinosaurs.pick_fleet(sid)
    _q = None
    if sub["pipeline_state"] not in ("complete", "failed"):
        _q = _queue_snapshot()
    return render_template(
        "submission.html",
        sub=sub,
        purchase_remaining=purchase_remaining,
        report_types=REPORT_TYPES,
        queue=_q,
        dino_svg=dino_svg,
        dino_flipped=dino_flipped,
        dino_index=dino_index,
        fleet=fleet,
        status_copy=STATUS_COPY.get(sub["pipeline_state"], "Processing"),
        status_sub=STATUS_SUB.get(sub["pipeline_state"], ""),
    )


@app.route("/s/<sid>/reports/<rtype>")
def report_proxy(sid: str, rtype: str):
    client, _ = ensure_client()
    if rtype not in REPORT_TYPES:
        abort(400)
    sub = db.get_submission_for_client(sid, client["id"])
    if sub is None:
        return render_template("expired.html"), 410
    if sub["pipeline_state"] != "complete":
        if sub["pipeline_state"] == "failed":
            abort(410, "analysis failed")
        abort(409, "analysis not complete yet")

    headers = {"X-Pipeline-Service-Token": PIPELINE_SERVICE_TOKEN}
    params = {"user_id": db.pipeline_user_id_for(client["id"])}
    try:
        with httpx.Client(timeout=30.0) as http:
            r = http.get(
                f"{PIPELINE_URL}/submissions/{sid}/reports/{rtype}",
                headers=headers, params=params,
            )
    except httpx.HTTPError as e:
        abort(502, f"upstream error: {e}")
    if r.status_code != 200:
        if r.status_code in (404, 410):
            return render_template("expired.html"), 410
        abort(r.status_code, r.text[:200])
    return Response(
        r.content,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{sid}-{rtype}.pdf"'},
    )


@app.route("/api/callback", methods=["POST"])
def callback():
    """Pipeline → webapp state notification.

    Authenticated by trace_id match against the stored row. Pipeline is the
    only client that knows the trace_id; UUIDv4 is unguessable. An unknown
    submission_id or mismatched trace_id is rejected.
    """
    payload = request.get_json(silent=True) or {}
    sid = payload.get("webapp_submission_id")
    trace_id = payload.get("trace_id")
    status = payload.get("status")
    if not sid or not trace_id or not status:
        return jsonify({"error": "missing fields"}), 400

    sub = db.get_submission_by_id(sid)
    if sub is None:
        return jsonify({"error": "unknown submission"}), 404
    if sub["trace_id"] != trace_id:
        app.logger.warning("callback trace_id mismatch sid=%s", sid)
        return jsonify({"error": "unauthorized"}), 403

    manifest = payload.get("report_manifest") or []
    error_code = payload.get("error_code")

    if status == "complete":
        db.update_submission_state(sid, "complete", report_manifest=manifest)
    elif status.startswith("failed_"):
        db.update_submission_state(sid, "failed", error_code=error_code or status)
    else:
        db.update_submission_state(sid, "analyzing")
    return jsonify({"ok": True}), 200

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/s/<sid>/checkout")
def checkout(sid: str):
    client, _ = ensure_client()
    sub = db.get_submission_for_client(sid, client["id"])
    if sub is None:
        return render_template("expired.html"), 410

    if sub["pipeline_state"] != "complete":
        flash("This submission is still being analyzed. Please wait for it to complete before purchasing.")
        return redirect(url_for("submission_detail", sid=sid))

    if sub["is_paid"]:
        return redirect(url_for("submission_detail", sid=sid))

    # Check if the purchase window has expired
    if _iso_seconds_remaining(sub["expires_at"]) <= 0:
        abort(403, "The purchase window for this archive has expired.")

    success_url = (
        url_for("submission_detail", sid=sid, _external=True)
        + "?payment=success&session_id={CHECKOUT_SESSION_ID}"
    )
    cancel_url = url_for("submission_detail", sid=sid, _external=True)

    checkout_url = stripe_handler.create_checkout_session(
        sid=sid,
        filename=sub["filename"],
        success_url=success_url,
        cancel_url=cancel_url
    )

    if checkout_url:
        return redirect(checkout_url)
    else:
        abort(500, "Failed to create Stripe checkout session")


@app.route("/s/<sid>/raw-export")
def raw_export_proxy(sid: str):
    """Stream the sanitized evidence archive from the pipeline API.

    Webapp proxies the request; the pipeline does the sanitize + tar work
    where the analyses directory lives. Same service-token auth as every
    other pipeline call. Browser never sees the pipeline URL.
    """
    client, _ = ensure_client()
    sub = db.get_submission_for_client(sid, client["id"])
    if sub is None:
        return render_template("expired.html"), 410
    if sub["pipeline_state"] != "complete":
        if sub["pipeline_state"] == "failed":
            abort(410, "analysis failed; archive unavailable")
        abort(409, "analysis not complete yet")
    if not sub["is_paid"]:
        abort(402, "payment required")

    headers = {"X-Pipeline-Service-Token": PIPELINE_SERVICE_TOKEN}
    params = {"user_id": db.pipeline_user_id_for(client["id"])}
    try:
        with httpx.Client(timeout=60.0) as http:
            r = http.get(
                f"{PIPELINE_URL}/submissions/{sid}/raw-export",
                headers=headers, params=params,
            )
    except httpx.HTTPError as e:
        log.error("raw-export upstream error sid=%s: %s", sid, e)
        abort(502, f"upstream error: {e}")

    if r.status_code == 200:
        return Response(
            r.content,
            mimetype="application/gzip",
            headers={
                "Content-Disposition":
                    f'attachment; filename="{sid}-raw-export.tar.gz"',
            },
        )
    if r.status_code == 410:
        abort(410, "archive is no longer available")
    if r.status_code == 404:
        abort(404, "submission not found")
    if r.status_code == 409:
        abort(409, "analysis not complete yet")
    log.error("raw-export upstream returned %d sid=%s body=%s",
              r.status_code, sid, r.text[:300])
    abort(502, f"pipeline returned {r.status_code}")



@app.errorhandler(413)
def too_large(_e):
    return jsonify({
        "error": "upload too large",
        "limit_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
    }), 413


@app.route("/api/stripe-webhook", methods=["POST"])
def stripe_webhook():
    """Stripe webhook receiver.

    Return codes control Stripe's retry policy:
      200 — handled (do not retry)
      400 — permanent failure: bad signature, bad payload, mismatched amount
            (do not retry)
      500 — transient failure: DB error, unexpected exception
            (Stripe retries with backoff for up to 3 days)
    """
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")
    try:
        success = stripe_handler.handle_webhook(payload, sig_header)
    except Exception as e:
        log.error(f"Webhook handler raised: {e}", exc_info=True)
        return jsonify({"status": "error"}), 500
    if success:
        return jsonify({"status": "success"}), 200
    return jsonify({"status": "failed"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
