"""Webapp-side SQLite for anonymous IP-based submissions.

No accounts. No login. Identity is a signed session cookie whose raw token
lives only in the browser; the database stores SHA-256(token). Client IP is
stored as SHA-256(ip || IP_HASH_SECRET)[:32] and never in plaintext.

Retention rule (locked):
  - submissions_cache.expires_at = max(created_at + 90min, completed_at + 60min)
  - clients.expires_at = last_seen_at + 90min (sliding on activity)
  - The pipeline purges its own rows and directories at completed_at + 90min;
    the webapp cleanup job purges its cache rows on the same schedule.
    Both are independent, no cross-service coordination needed.

Tables:
  - clients: one row per (ip_hash, session_token_hash). Sliding expiry.
  - submissions_cache: one row per submission. Fixed expiry with completion
    extension. Carries is_paid / stripe_session_id / paid_at for the $1 raw
    export feature.

The webapp is not the source of truth for analysis state; the pipeline is.
The cache exists so the dashboard renders without a network call per row.
"""
from __future__ import annotations
from contextlib import contextmanager

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

DB_PATH = Path("/opt/webapp/data/webapp.db")
PRAGMA_USER_VERSION = 1

# Total minimum lifetime of a submission, from creation.
TTL_SECONDS = 90 * 60            # 90 min

# Minimum purchase window from completion. Guarantees the user can pay for
# the raw export for at least 60 min after their analysis finishes, even if
# the analysis took most of the 90-min window.
PURCHASE_WINDOW_SECONDS = 60 * 60  # 60 min

VALID_WEBAPP_STATES = {
    "queued",
    "analyzing",
    "generating_reports",
    "complete",
    "failed",
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _future(seconds: int = TTL_SECONDS) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


@contextmanager
def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


def init() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ip_hash TEXT NOT NULL,
              session_token_hash TEXT NOT NULL UNIQUE,
              created_at TEXT NOT NULL,
              last_seen_at TEXT NOT NULL,
              expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS submissions_cache (
              webapp_submission_id TEXT PRIMARY KEY,
              client_id INTEGER NOT NULL,
              ip_hash TEXT NOT NULL,
              filename TEXT NOT NULL,
              file_size INTEGER,
              platform_requested TEXT,
              pipeline_state TEXT NOT NULL,
              error_code TEXT,
              trace_id TEXT,
              report_manifest_json TEXT NOT NULL DEFAULT '[]',
              is_paid INTEGER NOT NULL DEFAULT 0,
              stripe_session_id TEXT,
              paid_at TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_clients_expires
              ON clients(expires_at);
            CREATE INDEX IF NOT EXISTS idx_clients_ip
              ON clients(ip_hash);
            CREATE INDEX IF NOT EXISTS idx_sub_cache_client
              ON submissions_cache(client_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_sub_cache_state
              ON submissions_cache(pipeline_state);
            CREATE INDEX IF NOT EXISTS idx_sub_cache_expires
              ON submissions_cache(expires_at);
            CREATE INDEX IF NOT EXISTS idx_sub_cache_ip
              ON submissions_cache(ip_hash);
            """
        )

        cols = [r[1] for r in conn.execute("PRAGMA table_info(submissions_cache)").fetchall()]
        if "last_state_change_at" not in cols:
            conn.execute("ALTER TABLE submissions_cache ADD COLUMN last_state_change_at TEXT")
            conn.execute("UPDATE submissions_cache SET last_state_change_at = updated_at WHERE last_state_change_at IS NULL")

        conn.execute(f"PRAGMA user_version = {PRAGMA_USER_VERSION}")
        conn.commit()


# ----------------------------- privacy primitives -----------------------------

def compute_ip_hash(ip: str, secret: str) -> str:
    """Deterministic hash of the client IP. Not reversible without the secret."""
    return hashlib.sha256((ip + "|" + secret).encode("utf-8")).hexdigest()[:32]


def compute_session_token_hash(token: str) -> str:
    """Hash of the session token for DB storage. The raw token is never stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_session_token() -> str:
    """Cryptographically random session token, URL-safe, 256 bits."""
    return secrets.token_urlsafe(32)


def pipeline_user_id_for(client_id: int) -> str:
    """Stable mapping from webapp integer client id to pipeline string user_id.

    The pipeline uses this value as `user_id` in every API call and for its
    own IDOR checks, so it must never change for a given webapp client.
    Format is opaque to the pipeline — it just needs to be stable and
    unique per client.
    """
    return f"client_{client_id}"


# ----------------------------- clients -----------------------------

def get_or_create_client(ip_hash: str, session_token: str) -> dict:
    """Look up a client by session token hash. Create if missing or expired.

    On every call, updates last_seen_at and extends expires_at by TTL_SECONDS
    so an active user stays alive past their first 90 min, but an idle client
    is deleted after 90 min of inactivity.

    Returns the client row as a dict.
    """
    token_hash = compute_session_token_hash(session_token)
    now = _utcnow()
    new_exp = _future()
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM clients WHERE session_token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is not None and row["expires_at"] >= now:
            conn.execute(
                "UPDATE clients SET last_seen_at = ?, expires_at = ? WHERE id = ?",
                (now, new_exp, row["id"]),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM clients WHERE id = ?", (row["id"],)
            ).fetchone()
            return dict(row)

        if row is not None:
            conn.execute("DELETE FROM clients WHERE id = ?", (row["id"],))
            conn.commit()

        cur = conn.execute(
            "INSERT INTO clients "
            "(ip_hash, session_token_hash, created_at, last_seen_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (ip_hash, token_hash, now, now, new_exp),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM clients WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        return dict(row)


def get_client_by_session(session_token: str) -> Optional[dict]:
    token_hash = compute_session_token_hash(session_token)
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM clients WHERE session_token_hash = ?",
            (token_hash,),
        ).fetchone()
    if row is None:
        return None
    if row["expires_at"] < _utcnow():
        return None
    return dict(row)


def delete_client(client_id: int) -> bool:
    with _conn() as conn:
        cur = conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
        conn.commit()
        return cur.rowcount > 0


# ----------------------------- submissions cache -----------------------------

def insert_submission_cache(
    webapp_submission_id: str,
    client_id: int,
    ip_hash: str,
    filename: str,
    file_size: Optional[int],
    platform_requested: Optional[str],
    trace_id: str,
) -> None:
    """Insert a cache row in state 'queued'. Called before pipeline POST.

    expires_at starts at created_at + TTL_SECONDS (90 min) and is extended
    by update_submission_state when the submission reaches 'complete'.
    """
    now = _utcnow()
    exp = _future()
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO submissions_cache (
              webapp_submission_id, client_id, ip_hash, filename, file_size,
              platform_requested, pipeline_state, trace_id,
              created_at, updated_at, expires_at, last_state_change_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)
            """,
            (
                webapp_submission_id, client_id, ip_hash, filename, file_size,
                platform_requested, trace_id, now, now, exp, now,
            ),
        )
        conn.commit()


def update_submission_state(
    webapp_submission_id: str,
    pipeline_state: str,
    error_code: Optional[str] = None,
    report_manifest: Optional[list[dict]] = None,
) -> bool:
    """Update state + manifest, extending TTL on every call.

    TTL extends to max(existing expires_at, now + 60 min) on every update.
    For non-terminal states this keeps the row alive while the pipeline works
    (the webapp will not delete a submission the pipeline is still processing).
    For terminal states this guarantees a 60-min view/download window from
    completion or failure, then the normal cleanup sweep removes the row.
    """
    if pipeline_state not in VALID_WEBAPP_STATES:
        raise ValueError(f"invalid pipeline_state: {pipeline_state}")
    now = _utcnow()
    manifest_json = json.dumps(report_manifest or [])
    with _conn() as conn:
        row = conn.execute(
            "SELECT pipeline_state, expires_at, last_state_change_at "
            "FROM submissions_cache WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        ).fetchone()
        if row is None:
            return False
        new_exp = _future(PURCHASE_WINDOW_SECONDS)
        if row["expires_at"] > new_exp:
            new_exp = row["expires_at"]
        if row["pipeline_state"] == pipeline_state:
            new_change = row["last_state_change_at"] or now
        else:
            new_change = now
        cur = conn.execute(
            """
            UPDATE submissions_cache
            SET pipeline_state = ?, error_code = ?,
                report_manifest_json = ?, updated_at = ?, expires_at = ?
            WHERE webapp_submission_id = ?
            """,
            (pipeline_state, error_code, manifest_json, now, new_exp, webapp_submission_id),
        )
        conn.commit()
        return cur.rowcount > 0


def mark_paid(
    webapp_submission_id: str,
    stripe_session_id: str,
) -> bool:
    """Set is_paid=1 + extend TTL by 60 min from payment time. Idempotent."""
    now = _utcnow()
    with _conn() as conn:
        row = conn.execute(
            "SELECT expires_at FROM submissions_cache WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        ).fetchone()
        if row is None:
            return False
        new_exp = _future(PURCHASE_WINDOW_SECONDS)
        if row["expires_at"] > new_exp:
            new_exp = row["expires_at"]
        cur = conn.execute(
            "UPDATE submissions_cache "
            "SET is_paid = 1, stripe_session_id = ?, paid_at = ?, "
            "    updated_at = ?, expires_at = ? "
            "WHERE webapp_submission_id = ? AND is_paid = 0",
            (stripe_session_id, now, now, new_exp, webapp_submission_id),
        )
        conn.commit()
        return cur.rowcount > 0


def get_submission_for_client(
    webapp_submission_id: str, client_id: int
) -> Optional[dict]:
    """IDOR at webapp layer: returns None if client_id does not own the row."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM submissions_cache "
            "WHERE webapp_submission_id = ? AND client_id = ?",
            (webapp_submission_id, client_id),
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["report_manifest_json"] = json.loads(d.get("report_manifest_json") or "[]")
    except Exception:
        d["report_manifest_json"] = []
    return d


def list_submissions_for_client(
    client_id: int, limit: int = 50, offset: int = 0
) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM submissions_cache WHERE client_id = ? "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (client_id, limit, offset),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["report_manifest_json"] = json.loads(d.get("report_manifest_json") or "[]")
        except Exception:
            d["report_manifest_json"] = []
        out.append(d)
    return out


def get_stale_pending(older_than_seconds: int = 120) -> list[dict]:
    """Non-terminal submissions past threshold, for reconciliation sweep."""
    cutoff = (
        datetime.now(timezone.utc) - timedelta(seconds=older_than_seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM submissions_cache "
            "WHERE pipeline_state IN ('queued', 'analyzing', 'generating_reports') "
            "  AND updated_at < ? "
            "ORDER BY updated_at ASC LIMIT 100",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


# ----------------------------- expiry + cleanup primitives -----------------------------

def get_expired_submissions(now_iso: Optional[str] = None) -> list[dict]:
    now = now_iso or _utcnow()
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM submissions_cache WHERE expires_at < ? "
            "ORDER BY expires_at ASC LIMIT 200",
            (now,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_expired_clients(now_iso: Optional[str] = None) -> list[dict]:
    now = now_iso or _utcnow()
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM clients WHERE expires_at < ? "
            "ORDER BY expires_at ASC LIMIT 200",
            (now,),
        ).fetchall()
    return [dict(r) for r in rows]

def get_submission_by_id(webapp_submission_id: str) -> Optional[dict]:
    """Unscoped lookup by submission id.

    Only used by the pipeline callback receiver, which authenticates by
    trace_id match rather than by client ownership. Do not use this from any
    user-facing route; user routes must use get_submission_for_client() to
    enforce IDOR.
    """
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM submissions_cache WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["report_manifest_json"] = json.loads(d.get("report_manifest_json") or "[]")
    except Exception:
        d["report_manifest_json"] = []
    return d

def delete_submission(webapp_submission_id: str) -> bool:
    with _conn() as conn:
        cur = conn.execute(
            "DELETE FROM submissions_cache WHERE webapp_submission_id = ?",
            (webapp_submission_id,),
        )
        conn.commit()
        return cur.rowcount > 0


# ----------------------------- smoke test -----------------------------

def _smoke() -> int:
    """Run a full cycle on a temp DB. Never touches production data."""
    import tempfile

    global DB_PATH
    real_db = DB_PATH
    failures = 0

    with tempfile.TemporaryDirectory() as tmp:
        DB_PATH = Path(tmp) / "webapp.db"
        try:
            init()
        except Exception as e:
            print(f"FAIL init: {e}")
            return 1

        secret = "test-secret-do-not-use-in-prod"
        ip1 = "203.0.113.7"
        ip2 = "198.51.100.9"
        h1 = compute_ip_hash(ip1, secret)
        h2 = compute_ip_hash(ip2, secret)
        if h1 == h2 or len(h1) != 32:
            print("FAIL compute_ip_hash")
            failures += 1
        else:
            print(f"PASS compute_ip_hash len={len(h1)} distinct")

        tok1 = new_session_token()
        tok2 = new_session_token()
        if tok1 == tok2 or len(tok1) < 32:
            print("FAIL new_session_token")
            failures += 1
        else:
            print(f"PASS new_session_token len={len(tok1)} distinct")

        c1 = get_or_create_client(h1, tok1)
        if c1["id"] is None or c1["ip_hash"] != h1:
            print("FAIL get_or_create_client create")
            failures += 1
        else:
            print(f"PASS get_or_create_client id={c1['id']}")

        c1b = get_or_create_client(h1, tok1)
        if c1b["id"] != c1["id"]:
            print("FAIL get_or_create_client same session returned different id")
            failures += 1
        else:
            print("PASS get_or_create_client idempotent for same session")

        c2 = get_or_create_client(h2, tok2)
        if c2["id"] == c1["id"]:
            print("FAIL different session got same client")
            failures += 1
        else:
            print(f"PASS distinct session -> distinct client id={c2['id']}")

        sid = "11111111-1111-4111-8111-111111111111"
        insert_submission_cache(sid, c1["id"], h1, "sample.exe", 11264, "windows", "trace-1")
        row = get_submission_for_client(sid, c1["id"])
        if not row or row["pipeline_state"] != "queued":
            print("FAIL insert_submission_cache queued")
            failures += 1
        else:
            print("PASS insert_submission_cache queued")

        # 90-min initial TTL check
        from datetime import datetime as _dt, timezone as _tz, timedelta as _td
        exp = _dt.strptime(row["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_tz.utc)
        want_min = _dt.now(_tz.utc) + _td(seconds=TTL_SECONDS - 60)
        if exp < want_min:
            print(f"FAIL insert expires_at too soon: {row['expires_at']}")
            failures += 1
        else:
            print(f"PASS insert expires_at >= now + {TTL_SECONDS - 60}s")

        if get_submission_for_client(sid, c2["id"]) is not None:
            print("FAIL IDOR: client c2 sees c1's submission")
            failures += 1
        else:
            print("PASS IDOR blocked")

        manifest = [{"type": "executive_risk", "sha256": "0" * 64,
                     "generated_at": "2026-10-31T00:00:00Z",
                     "relative_path": f"{sid}/executive_risk.pdf"}]
        ok = update_submission_state(sid, "complete", report_manifest=manifest)
        row = get_submission_for_client(sid, c1["id"])
        if not ok or row["pipeline_state"] != "complete" or len(row["report_manifest_json"]) != 1:
            print("FAIL update_submission_state complete")
            failures += 1
        else:
            print("PASS update_submission_state complete with manifest")

        # Purchase window check: after complete, expires_at must be at least
        # now + PURCHASE_WINDOW_SECONDS - 60 (allow small clock slack)
        exp_after = _dt.strptime(row["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_tz.utc)
        want_min = _dt.now(_tz.utc) + _td(seconds=PURCHASE_WINDOW_SECONDS - 60)
        if exp_after < want_min:
            print(f"FAIL complete did not extend purchase window: {row['expires_at']}")
            failures += 1
        else:
            print(f"PASS complete extends expires_at >= now + {PURCHASE_WINDOW_SECONDS - 60}s")

        if row["is_paid"] != 0:
            print("FAIL is_paid default should be 0")
            failures += 1
        else:
            print("PASS is_paid default 0")

        if mark_paid(sid, "cs_test_ABC123"):
            row = get_submission_for_client(sid, c1["id"])
            if row["is_paid"] != 1 or row["stripe_session_id"] != "cs_test_ABC123":
                print("FAIL mark_paid values")
                failures += 1
            else:
                print("PASS mark_paid")
        else:
            print("FAIL mark_paid returned False")
            failures += 1

        if mark_paid(sid, "cs_test_SECOND"):
            print("FAIL mark_paid not idempotent")
            failures += 1
        else:
            print("PASS mark_paid idempotent")

        # Force-expire: backdate expires_at and verify get_expired finds it
        with _conn() as conn:
            conn.execute(
                "UPDATE submissions_cache SET expires_at = ? WHERE webapp_submission_id = ?",
                ("2020-01-01T00:00:00Z", sid),
            )
            conn.commit()
        expired_subs = get_expired_submissions()
        if not any(s["webapp_submission_id"] == sid for s in expired_subs):
            print("FAIL get_expired_submissions")
            failures += 1
        else:
            print("PASS get_expired_submissions")

        delete_submission(sid)
        if get_submission_for_client(sid, c1["id"]) is not None:
            print("FAIL delete_submission")
            failures += 1
        else:
            print("PASS delete_submission")

        # Force-expire client c2 and delete it
        with _conn() as conn:
            conn.execute(
                "UPDATE clients SET expires_at = ? WHERE id = ?",
                ("2020-01-01T00:00:00Z", c2["id"]),
            )
            conn.commit()
        expired_clients = get_expired_clients()
        if not any(c["id"] == c2["id"] for c in expired_clients):
            print("FAIL get_expired_clients")
            failures += 1
        else:
            print("PASS get_expired_clients")

        if delete_client(c2["id"]):
            print("PASS delete_client")
        else:
            print("FAIL delete_client returned False")
            failures += 1

        if get_client_by_session(tok1) is None:
            print("FAIL get_client_by_session c1 unexpectedly gone")
            failures += 1
        else:
            print("PASS get_client_by_session c1 alive")

    DB_PATH = real_db
    if failures:
        print(f"{failures} failure(s)")
        return 1
    print("all webapp db checks passed")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_smoke())
