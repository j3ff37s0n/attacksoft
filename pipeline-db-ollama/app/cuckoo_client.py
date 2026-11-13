"""Cuckoo integration: submit samples, poll state, fetch finished task artifacts.

Everything goes over SSH as `capeadmin` on the Cuckoo host. No sudo, no wrapper.
The Cuckoo host already has `capeadmin` in the docker group; submission is
`docker compose exec cuckoo cuckoo submit` piped through SSH stdin.

Task ID format: YYYYMMDD-XXXXX (e.g., 20261031-LMMNWK).
Analysis directory: <analyses_root>/<YYYYMMDD>/<XXXXX>/
  - The directory uses only the SHORT portion after the dash.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

SSH_HOST = "capeadmin@<internal_ip>"
SSH_KEY = "/opt/pipeline/.ssh/cuckoo_key"
SSH_OPTS = [
    "-i", SSH_KEY,
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=10",
]

REMOTE_ANALYSES_ROOT = "/srv/cuckoo3/config/.cuckoocwd/storage/analyses"
REMOTE_STAGING_DIR = "/srv/cuckoo3/config/.cuckoocwd/.pipeline-staging"
REMOTE_CONTAINER_STAGING = "/home/cuckoo/.cuckoocwd/.pipeline-staging"
REMOTE_COMPOSE_DIR = "/srv/cuckoo3"

LOCAL_ANALYSES_ROOT = Path("/opt/pipeline/data/analyses")

SUBMIT_TIMEOUT_S = 120
STATUS_TIMEOUT_S = 20
FETCH_TIMEOUT_S = 300

TERMINAL_SUCCESS = {"finished", "reported"}
TERMINAL_FAILURE = {"failed", "error", "aborted", "timeout", "no_selected"}
INDETERMINATE = {"NO_FILE", "INVALID_JSON", "UNKNOWN", "EMPTY"}

PLATFORMS = {"windows", "linux"}


def _split_task_id(task_id: str) -> tuple[str, str]:
    """Split YYYYMMDD-XXXXX into (date, short_id). Raise on malformed input."""
    if "-" not in task_id:
        raise ValueError(f"malformed task_id (no dash): {task_id!r}")
    date, short = task_id.split("-", 1)
    if len(date) != 8 or not date.isdigit():
        raise ValueError(f"malformed task_id date: {task_id!r}")
    if not short or not all(c.isalnum() or c == "_" for c in short):
        raise ValueError(f"malformed task_id short: {task_id!r}")
    return date, short


def detect_platform(file_path: Path) -> str:
    """Return 'windows', 'linux', or '' from magic bytes."""
    with file_path.open("rb") as f:
        head = f.read(4)
    if head[:2] == b"MZ":
        return "windows"
    if head[:4] == b"\x7fELF":
        return "linux"
    return ""


def submit_sample(file_path: Path, platform: str | None = None, timeout_s: int = SUBMIT_TIMEOUT_S) -> str:
    """Submit a local file to Cuckoo via SSH stdin. Returns the task_id.

    Raises RuntimeError if the SSH command fails or the task_id cannot be parsed.
    """
    if not file_path.is_file():
        raise FileNotFoundError(f"sample not found: {file_path}")

    if platform is None:
        platform = detect_platform(file_path)
    if platform not in PLATFORMS:
        raise ValueError(
            f"cannot detect platform for {file_path} "
            f"(magic bytes neither MZ nor ELF); pass platform explicitly"
        )

    # Heredoc-style script sent over SSH. Uses set -euo pipefail; stdin is the
    # sample payload which lands in TMPFILE before submit reads it.
    script = f"""
set -euo pipefail
UUID=$(cat /proc/sys/kernel/random/uuid)
STAGE="{REMOTE_STAGING_DIR}"
TMPFILE="$STAGE/$UUID.bin"
trap 'rm -f "$TMPFILE"' EXIT
cat > "$TMPFILE"
chmod 0644 "$TMPFILE"
cd "{REMOTE_COMPOSE_DIR}"
docker compose exec -T cuckoo cuckoo submit --platform "{platform}" "{REMOTE_CONTAINER_STAGING}/$UUID.bin"
"""

    log.info("cuckoo submit: file=%s platform=%s size=%d", file_path.name, platform, file_path.stat().st_size)
    result = subprocess.run(
        ["ssh", *SSH_OPTS, SSH_HOST, script],
        input=file_path.read_bytes(),
        capture_output=True,
        timeout=timeout_s,
    )
    stdout = result.stdout.decode(errors="replace")
    stderr = result.stderr.decode(errors="replace")

    if result.returncode != 0:
        raise RuntimeError(
            f"cuckoo submit failed (exit={result.returncode}): "
            f"stderr={stderr[:500]!r} stdout={stdout[:300]!r}"
        )

    # Parse: "Submitted file: 20261031-LMMNWK -> /home/cuckoo/..."
    import re
    m = re.search(r"Submitted file:\s*([0-9]{8}-[A-Z0-9]+)\s*->", stdout)
    if not m:
        raise RuntimeError(
            f"cannot parse task_id from submit output: stdout={stdout[:300]!r} stderr={stderr[:300]!r}"
        )
    task_id = m.group(1)
    log.info("cuckoo submit: task_id=%s", task_id)
    return task_id


def get_task_state(task_id: str, timeout_s: int = STATUS_TIMEOUT_S) -> tuple[str, dict | None]:
    """Read analysis.json for a task. Returns (state, parsed_json_or_None).

    state is one of: 'finished', 'reported', 'failed', 'error', 'aborted',
    'timeout', 'running', 'pending', 'NO_FILE', 'INVALID_JSON', 'EMPTY',
    or whatever string Cuckoo wrote in the field.
    """
    date, short = _split_task_id(task_id)
    remote_json = f"{REMOTE_ANALYSES_ROOT}/{date}/{short}/analysis.json"
    cmd = f"cat {remote_json} 2>/dev/null || true"
    result = subprocess.run(
        ["ssh", *SSH_OPTS, SSH_HOST, cmd],
        capture_output=True,
        timeout=timeout_s,
    )
    if result.returncode != 0:
        log.warning("cuckoo state ssh failed task=%s exit=%d", task_id, result.returncode)
        return "UNKNOWN", None
    raw = result.stdout.decode(errors="replace").strip()
    if not raw:
        return "NO_FILE", None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return "INVALID_JSON", None
    return data.get("state", "UNKNOWN"), data


def is_terminal(state: str) -> bool:
    return state in TERMINAL_SUCCESS or state in TERMINAL_FAILURE or state in INDETERMINATE


def is_terminal_success(state: str) -> bool:
    return state in TERMINAL_SUCCESS


def is_terminal_failure(state: str) -> bool:
    return state in TERMINAL_FAILURE


def fetch_task_artifacts(task_id: str, local_target: Path | None = None, timeout_s: int = FETCH_TIMEOUT_S) -> Path:
    """Rsync a finished task's analysis directory from Cuckoo to local disk.

    Excludes memory/ (dumps are not used and can be hundreds of MB).
    Returns the local directory path.
    """
    date, short = _split_task_id(task_id)
    remote_dir = f"{REMOTE_ANALYSES_ROOT}/{date}/{short}"
    if local_target is None:
        local_target = LOCAL_ANALYSES_ROOT / task_id
    if local_target.exists():
        shutil.rmtree(local_target)
    local_target.mkdir(parents=True, exist_ok=False)

    # Trailing slash on remote source = copy contents, not the directory itself.
    rsync_cmd = [
        "rsync", "-a", "--exclude=memory",
        "-e", "ssh " + " ".join(SSH_OPTS),
        f"{SSH_HOST}:{remote_dir}/",
        str(local_target) + "/",
    ]
    log.info("cuckoo fetch: task=%s target=%s", task_id, local_target)
    result = subprocess.run(rsync_cmd, capture_output=True, timeout=timeout_s)
    if result.returncode != 0:
        raise RuntimeError(
            f"rsync failed (exit={result.returncode}): {result.stderr.decode(errors='replace')[:500]}"
        )

    if not (local_target / "analysis.json").is_file():
        raise RuntimeError(f"fetched task dir has no analysis.json: {local_target}")

    log.info("cuckoo fetch complete: task=%s bytes=%d", task_id, _du_bytes(local_target))
    return local_target


def _du_bytes(p: Path) -> int:
    total = 0
    for f in p.rglob("*"):
        if f.is_file() and not f.is_symlink():
            try:
                total += f.stat().st_size
            except OSError:
                pass
    return total


def delete_task(task_id: str, timeout_s: int = 30) -> bool:
    """Delete a task's analysis directory on the cuckoo host over SSH.

    Called from:
      - _handle_sandbox_complete: after evidence_bundle.json is written, so
        cuckoo's copy is removed once the pipeline owns the data (privacy).
      - _handle_poll: on stuck-state timeout, before _fail(), so orphaned
        tasks don't accumulate in cuckoo storage.

    task_id is validated by _split_task_id before it hits the shell command.
    Returns True if the directory was removed, False otherwise.
    """
    try:
        date, short = _split_task_id(task_id)
    except ValueError as e:
        log.warning("delete_task bad task_id %r: %s", task_id, e)
        return False

    container_dir = f"/home/cuckoo/.cuckoocwd/storage/analyses/{date}/{short}"
    cmd = (
        f"cd {REMOTE_COMPOSE_DIR} && "
        f"docker compose exec -T cuckoo rm -rf {container_dir} && "
        f"echo __DELETED__"
    )
    try:
        result = subprocess.run(
            ["ssh", *SSH_OPTS, SSH_HOST, cmd],
            capture_output=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        log.warning("delete_task timeout task=%s", task_id)
        return False
    if result.returncode != 0:
        log.warning(
            "delete_task ssh failed task=%s exit=%d stderr=%s",
            task_id, result.returncode,
            result.stderr.decode(errors="replace")[:300],
        )
        return False
    if b"__DELETED__" not in result.stdout:
        log.warning(
            "delete_task marker missing task=%s stdout=%r stderr=%r",
            task_id,
            result.stdout[:200], result.stderr[:200],
        )
        return False
    log.info("cuckoo delete: task=%s dir=%s", task_id, container_dir)
    return True


def cleanup_local_artifacts(task_id: str) -> bool:
    """Remove the local analysis directory for a task. Returns True if removed."""
    date, short = _split_task_id(task_id)
    target = LOCAL_ANALYSES_ROOT / task_id
    if target.exists():
        shutil.rmtree(target)
        return True
    return False
