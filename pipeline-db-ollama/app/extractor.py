"""Evidence extractor: parse a Cuckoo3 analysis directory into a normalized
evidence bundle that conforms to evidence_bundle.schema.json.

Design notes:
- Facts are extracted at field granularity (one fact per notable value), not
  one per event. This keeps each fact's verbatim short enough to survive the
  prompt truncation (400 chars) and keeps citations unambiguous.
- pcap is authoritative for network facts: pcap-derived facts set
  authoritative=true. Sysmon network facts are also emitted but with
  authoritative=false so the LLM/verifier can prefer pcap where they conflict.
- Missing sysmon.json produces insufficient_evidence entries for event-based
  sections and does NOT fail the extraction.
- Multi-task selection: pick the task_N directory with the most facts, tiebreak
  lowest N. Non-selected tasks are recorded in task_selection.additional_tasks.
- The binary symlink is realpath-resolved and hashed; if the target is missing
  on this host, the fact's parser_status is "absent" and it lands in
  insufficient_evidence.
- Every fact carries source.sha256 so downstream verification can trace it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

EXTRACTOR_VERSION = "extractor/1.0"

SYSMON_PROCESS_CREATE = 1
SYSMON_NETWORK_CONNECT = 3
SYSMON_FILE_CREATE = 11
SYSMON_DNS_QUERY = 22
SYSMON_FILE_DELETE = 23
SYSMON_IMAGE_LOAD = 7
SYSMON_PROCESS_ACCESS = 10
SYSMON_REGISTRY_CREATE = 12
SYSMON_REGISTRY_SET = 13
SYSMON_PROCESS_TERMINATE = 5
SYSMON_CREATE_REMOTE_THREAD = 8
SYSMON_REGISTRY_RENAME = 14
SYSMON_FILE_DELETE_DETECTED = 26
SYSMON_CLIPBOARD_CHANGE = 24
SYSMON_PROCESS_TAMPERING = 25

CUCKOO_DATE_RE = re.compile(r"/Date\((\d+)\)/")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_cuckoo_date(value: Any) -> str | None:
    """Convert Cuckoo's {'__isodt__': '...'} or '/Date(ms)/' to RFC3339 UTC."""
    if isinstance(value, dict) and "__isodt__" in value:
        try:
            dt = datetime.fromisoformat(value["__isodt__"])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return None
    if isinstance(value, str):
        m = CUCKOO_DATE_RE.fullmatch(value)
        if m:
            try:
                dt = datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                return None
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return None
    return None


class _Builder:
    """Accumulates facts and tracks per-category counters for stable IDs."""

    def __init__(self):
        self.facts: list[dict] = []
        self._counters: dict[str, int] = {}
        self._sha_cache: dict[Path, str] = {}

    def sha256_of(self, path: Path) -> str:
        if path not in self._sha_cache:
            self._sha_cache[path] = _sha256_file(path)
        return self._sha_cache[path]

    def add(
        self,
        category: str,
        key: str,
        value: Any,
        verbatim: str,
        artifact: str,
        artifact_sha256: str,
        locator: str,
        authoritative: bool = False,
    ) -> str:
        n = self._counters.get(category, 0) + 1
        self._counters[category] = n
        fact_id = f"f_{category}_{n:03d}"
        self.facts.append(
            {
                "fact_id": fact_id,
                "category": category,
                "key": key,
                "value": value,
                "source": {
                    "source_type": "artifact",
                    "source_id": artifact,
                    "artifact": artifact,
                    "locator": locator,
                    "sha256": artifact_sha256,
                    "verbatim": verbatim,
                },
                "verbatim": verbatim,
                "authoritative": authoritative,
            }
        )
        return fact_id


def _file_artifact_entry(
    name: str, rel: str, path: Path, parser_status: str, parser_error: str | None = None
) -> dict:
    if path.is_file():
        return {
            "artifact_name": name,
            "relative_path": rel,
            "present": True,
            "size_bytes": path.stat().st_size,
            "sha256": _sha256_file(path),
            "parser_status": parser_status,
            "parser_error": parser_error,
        }
    return {
        "artifact_name": name,
        "relative_path": rel,
        "present": False,
        "size_bytes": None,
        "sha256": None,
        "parser_status": "absent",
        "parser_error": parser_error,
    }


def _load_json(path: Path) -> tuple[dict | list | None, str | None]:
    if not path.is_file():
        return None, "absent"
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace").strip()
    except Exception as exc:
        return None, f"read_error:{exc}"
    if not text:
        return None, "empty"
    try:
        return json.loads(text), None
    except Exception as exc:
        return None, f"parse_error:{exc}"


def _extract_analysis_metadata(analysis_dir: Path, b: _Builder, artifacts: list) -> dict:
    path = analysis_dir / "analysis.json"
    data, err = _load_json(path)
    if data is None:
        artifacts.append(_file_artifact_entry("analysis.json", "analysis.json", path, err or "absent", err))
        return {}
    artifacts.append(_file_artifact_entry("analysis.json", "analysis.json", path, "parsed"))
    sha = b.sha256_of(path)
    tgt = data.get("target", {}) or {}
    submitted = data.get("submitted", {}) or {}

    for key, value in [
        ("filename", tgt.get("filename")),
        ("orig_filename", tgt.get("orig_filename")),
        ("primary_filename", tgt.get("orig_filename") or tgt.get("filename")),
        ("filetype", tgt.get("filetype")),
        ("media_type", tgt.get("media_type")),
        ("md5", submitted.get("md5") or tgt.get("md5")),
        ("sha1", submitted.get("sha1") or tgt.get("sha1")),
        ("sha256", submitted.get("sha256") or tgt.get("sha256")),
        ("sha512", submitted.get("sha512") or tgt.get("sha512")),
    ]:
        if value:
            b.add("metadata", key, value, str(value), "analysis.json", sha, f"target.{key}")
    for key in ("size",):
        value = tgt.get(key) or submitted.get(key)
        if isinstance(value, (int, float)):
            b.add("metadata", f"file_{key}", value, str(value), "analysis.json", sha, f"target.{key}")
    for key in ("id", "category", "state", "score", "kind"):
        v = data.get(key)
        if v is not None:
            b.add("metadata", key, v, str(v), "analysis.json", sha, key)
    created = _parse_cuckoo_date(data.get("created_on"))
    if created:
        b.add("metadata", "created_on_utc", created, created, "analysis.json", sha, "created_on")
    return data


def _extract_task_metadata(task_dir: Path, b: _Builder, artifacts: list) -> dict:
    path = task_dir / "task.json"
    rel = f"{task_dir.name}/task.json"
    data, err = _load_json(path)
    if data is None:
        artifacts.append(_file_artifact_entry("task.json", rel, path, err or "absent", err))
        return {}
    artifacts.append(_file_artifact_entry("task.json", rel, path, "parsed"))
    sha = b.sha256_of(path)
    for key in ("id", "state", "platform", "os_version", "score"):
        v = data.get(key)
        if v is not None and v != "":
            b.add("metadata", f"task_{key}", v, str(v), rel, sha, key)
    return data


def _extract_filetree(analysis_dir: Path, b: _Builder, artifacts: list) -> dict:
    path = analysis_dir / "filetree.json"
    data, err = _load_json(path)
    if data is None:
        artifacts.append(_file_artifact_entry("filetree.json", "filetree.json", path, err or "absent", err))
        return {}
    artifacts.append(_file_artifact_entry("filetree.json", "filetree.json", path, "parsed"))
    sha = b.sha256_of(path)
    if isinstance(data, dict):
        for key, val in [
            ("filename", data.get("filename")),
            ("human_type", data.get("human_type")),
            ("extension", data.get("extension")),
        ]:
            if val:
                b.add("file", f"tree_{key}", val, str(val), "filetree.json", sha, key)
        finger = data.get("finger", {}) or {}
        for key in ("mime", "magic"):
            if finger.get(key):
                b.add("file", f"tree_finger_{key}", finger[key], str(finger[key]), "filetree.json", sha, f"finger.{key}")
        if "safelisted" in data:
            b.add("file", "safelisted", data["safelisted"], str(data["safelisted"]).lower(), "filetree.json", sha, "safelisted")
    return data


def _extract_pre_static(analysis_dir: Path, b: _Builder, artifacts: list) -> dict:
    path = analysis_dir / "pre.json"
    data, err = _load_json(path)
    if data is None:
        artifacts.append(_file_artifact_entry("pre.json", "pre.json", path, err or "absent", err))
        return {}
    artifacts.append(_file_artifact_entry("pre.json", "pre.json", path, "parsed"))
    sha = b.sha256_of(path)
    static = data.get("static", {}) or {}
    pe = static.get("pe", {}) or {}

    for sig in pe.get("peid_signatures", []) or []:
        b.add("metadata", "peid_signature", sig, str(sig), "pre.json", sha, "static.pe.peid_signatures")
    if pe.get("pe_imphash"):
        b.add("file", "pe_imphash", pe["pe_imphash"], str(pe["pe_imphash"]), "pre.json", sha, "static.pe.pe_imphash")
    if pe.get("pe_timestamp"):
        b.add("file", "pe_timestamp", pe["pe_timestamp"], str(pe["pe_timestamp"]), "pre.json", sha, "static.pe.pe_timestamp")
    for ver in pe.get("pe_versioninfo", []) or []:
        name = ver.get("name")
        value = ver.get("value")
        if name and value:
            b.add("metadata", f"versioninfo_{name}", value, str(value), "pre.json", sha, f"pe_versioninfo.{name}")
    for imp in pe.get("pe_imports", []) or []:
        dll = imp.get("dll", "")
        for entry in imp.get("imports", []) or []:
            fn = entry.get("name", "")
            if dll and fn:
                b.add("file", "pe_import", f"{dll}!{fn}", f"{dll}!{fn}", "pre.json", sha, "pe_imports")
    for sec in pe.get("pe_sections", []) or []:
        name = sec.get("name", "")
        entropy = sec.get("entropy")
        if name:
            b.add("file", "pe_section", f"{name} entropy={entropy}", f"{name} entropy={entropy}", "pre.json", sha, "pe_sections")
    for res in pe.get("pe_resources", []) or []:
        name = res.get("name", "")
        ftype = res.get("filetype", "")
        if name:
            b.add("file", "pe_resource", f"{name} {ftype}", f"{name} {ftype}", "pre.json", sha, "pe_resources")
    sigs = pe.get("signatures", []) or []
    if not sigs:
        b.add("metadata", "code_signatures", "none", "none", "pre.json", sha, "static.pe.signatures")
    return data


def _extract_agent_analysis(task_dir: Path, b: _Builder, artifacts: list) -> dict:
    path = task_dir / "agent_analysis.json"
    rel = f"{task_dir.name}/agent_analysis.json"
    data, err = _load_json(path)
    if data is None:
        artifacts.append(_file_artifact_entry("agent_analysis.json", rel, path, err or "absent", err))
        return {}
    artifacts.append(_file_artifact_entry("agent_analysis.json", rel, path, "parsed"))
    sha = b.sha256_of(path)
    events = data.get("events", []) if isinstance(data, dict) else []
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            continue
        d = ev.get("data", {}) or {}
        if ev.get("event_type") == "screenshot":
            shot_path = d.get("path")
            shot_ts = d.get("ts")
            if shot_path:
                b.add("screenshot", "captured_path", shot_path, shot_path, rel, sha,
                      f"events[{i}].data.path")
            if shot_ts is not None:
                try:
                    import datetime as _dt
                    ts_iso = _dt.datetime.fromtimestamp(int(shot_ts), tz=_dt.timezone.utc).isoformat()
                except Exception:
                    ts_iso = str(shot_ts)
                b.add("screenshot", "captured_at", ts_iso, ts_iso, rel, sha,
                      f"events[{i}].data.ts")

        if ev.get("event_type") == "download_watch":
            _orig = d.get("original_path")
            if _orig:
                b.add("file", "downloaded_by_sample", _orig, _orig, rel, sha,
                      f"events[{i}].data.original_path")
            _dl_sha = d.get("sha256")
            if _dl_sha:
                b.add("file", "downloaded_sha256", _dl_sha, _dl_sha, rel, sha,
                      f"events[{i}].data.sha256")
            _exe_pid = d.get("executed_pid")
            if _exe_pid is not None:
                b.add("process", "downloaded_was_executed_pid", str(_exe_pid),
                      str(_exe_pid), rel, sha, f"events[{i}].data.executed_pid")

        shots_taken = d.get("shots_taken")
        if shots_taken is not None and shots_taken > 0:
            b.add("screenshot", "total_captured", str(shots_taken), str(shots_taken), rel, sha,
                  f"events[{i}].data.shots_taken")

        cmd = d.get("command")
        if cmd:
            b.add("process", "monitored_execution", cmd, cmd, rel, sha, f"events[{i}].data.command")
        cwd = d.get("cwd")
        if cwd:
            b.add("file", "execution_cwd", cwd, cwd, rel, sha, f"events[{i}].data.cwd")
        stderr = d.get("stderr")
        if stderr:
            b.add("process", "execution_stderr", stderr, stderr, rel, sha, f"events[{i}].data.stderr")
        new_files = d.get("new_files")
        if isinstance(new_files, list):
            for j, nf in enumerate(new_files):
                if isinstance(nf, str) and nf:
                    b.add("file", "created_by_sample", nf, nf, rel, sha,
                          f"events[{i}].data.new_files[{j}]")


        exit_code = d.get("exit_code")
        if exit_code is not None:
            b.add("process", "execution_exit_code", exit_code, str(exit_code), rel, sha, f"events[{i}].data.exit_code")
    return data

def _build_sample_process_tree(data, sample_names, sample_hashes):
    """Return (relevant_guids, relevant_pids, root_count, mode).

    Modes:
      "windows" — ProcessGuid + ParentProcessGuid
      "linux"   — ProcessGuid + ParentProcessId (Cuckoo Linux agent)
      "pid"     — ProcessId + ParentProcessId (no GUIDs)
      None      — no parent linkage available; caller emits all events unchanged
    """
    from collections import defaultdict

    def _parse_ev(ev):
        if not isinstance(ev, dict):
            return None, {}
        eid = ev.get("Id") or ev.get("EventID")
        msg = ev.get("Message", "")
        if eid is None and msg:
            header = msg.replace("\r\n", "\n").split("\n")[0].rstrip(":").strip()
            for h_key, h_eid in HEADER_TO_EID.items():
                if header.startswith(h_key):
                    eid = h_eid
                    break
        fields = {}
        for line in (msg or "").replace("\r\n", "\n").split("\n")[1:]:
            m = re.match(r"^([A-Za-z][A-Za-z0-9_]*):\s*(.*)$", line)
            if m:
                fields[m.group(1)] = m.group(2).strip()
        return eid, fields

    has_guid = has_parent_guid = has_pid = has_parent_pid = False
    for ev in data:
        eid, f = _parse_ev(ev)
        if eid != SYSMON_PROCESS_CREATE:
            continue
        if f.get("ProcessGuid"):
            has_guid = True
        if f.get("ParentProcessGuid"):
            has_parent_guid = True
        if f.get("ProcessId"):
            has_pid = True
        if f.get("ParentProcessId"):
            has_parent_pid = True

    if has_guid and has_parent_guid:
        mode = "windows"
    elif has_guid and has_parent_pid:
        mode = "linux"
    elif has_pid and has_parent_pid:
        mode = "pid"
    else:
        log.warning(
            "sysmon filter: no parent linkage found "
            "(has_guid=%s has_parent_guid=%s has_pid=%s has_parent_pid=%s). "
            "Emitting all events unchanged.",
            has_guid, has_parent_guid, has_pid, has_parent_pid,
        )
        return set(), set(), 0, None

    pid_to_guid = {}
    guid_to_pid = {}
    children_by_guid = defaultdict(list)
    children_by_ppid = defaultdict(list)
    roots_guid = []
    roots_pid = []

    for ev in data:
        eid, f = _parse_ev(ev)
        if eid != SYSMON_PROCESS_CREATE:
            continue
        guid = f.get("ProcessGuid", "").strip()
        pid_s = f.get("ProcessId", "").strip()
        ppguid = f.get("ParentProcessGuid", "").strip()
        ppid_s = f.get("ParentProcessId", "").strip()
        image = f.get("Image", "")
        cmdline = f.get("CommandLine", "")
        try:
            pid = int(pid_s) if pid_s else None
        except ValueError:
            pid = None
        try:
            ppid = int(ppid_s) if ppid_s else None
        except ValueError:
            ppid = None

        if guid and pid is not None:
            pid_to_guid[pid] = guid
            guid_to_pid[guid] = pid
        if ppguid and guid:
            children_by_guid[ppguid].append(guid)
        if ppid is not None and guid:
            children_by_ppid[ppid].append(guid)

        image_basename = image.replace("/", "\\").split("\\")[-1].lower()
        cmdline_lower = cmdline.lower()
        is_root = (
            image_basename in sample_names
            or any(h in cmdline_lower for h in sample_hashes)
            or any(
                (f"\\{name}" in cmdline_lower or f"/{name}" in cmdline_lower)
                for name in sample_names if len(name) > 3
            )
        )
        if is_root:
            if guid:
                roots_guid.append(guid)
            if pid is not None:
                roots_pid.append(pid)

    if mode == "windows":
        relevant_guids = set(roots_guid)
        queue = list(roots_guid)
        while queue:
            g = queue.pop()
            for child_g in children_by_guid.get(g, []):
                if child_g not in relevant_guids:
                    relevant_guids.add(child_g)
                    queue.append(child_g)
        return relevant_guids, set(), len(roots_guid), mode

    if mode == "linux":
        relevant_guids = set(roots_guid)
        queue = list(roots_guid)
        while queue:
            g = queue.pop()
            pid = guid_to_pid.get(g)
            if pid is None:
                continue
            for child_g in children_by_ppid.get(pid, []):
                if child_g not in relevant_guids:
                    relevant_guids.add(child_g)
                    queue.append(child_g)
        relevant_pids = {guid_to_pid[g] for g in relevant_guids if g in guid_to_pid}
        return relevant_guids, relevant_pids, len(roots_guid), mode

    relevant_pids = set(roots_pid)
    queue = list(roots_pid)
    while queue:
        p = queue.pop()
        for child_g in children_by_ppid.get(p, []):
            child_pid = guid_to_pid.get(child_g)
            if child_pid is not None and child_pid not in relevant_pids:
                relevant_pids.add(child_pid)
                queue.append(child_pid)
    return set(), relevant_pids, len(roots_pid), mode


def _extract_sysmon(task_dir: Path, b: _Builder, artifacts: list,
                    sample_names: set, sample_hashes: set) -> tuple[dict | None, bool]:
    path = task_dir / "sysmon.json"
    rel = f"{task_dir.name}/sysmon.json"
    if not path.is_file():
        artifacts.append(_file_artifact_entry("sysmon.json", rel, path, "absent"))
        return None, False
    data, err = _load_json(path)
    if data is None:
        artifacts.append(_file_artifact_entry("sysmon.json", rel, path, err or "absent", err))
        return None, False
    artifacts.append(_file_artifact_entry("sysmon.json", rel, path, "parsed"))
    sha = b.sha256_of(path)
    if not isinstance(data, list):
        return {}, True

    HEADER_TO_EID = {
        "Process Create": SYSMON_PROCESS_CREATE,
        "Process created": SYSMON_PROCESS_CREATE,
        "Network connection detected": SYSMON_NETWORK_CONNECT,
        "Process terminated": SYSMON_PROCESS_TERMINATE,
        "Image loaded": SYSMON_IMAGE_LOAD,
        "Remote thread created": SYSMON_CREATE_REMOTE_THREAD,
        "Process accessed": SYSMON_PROCESS_ACCESS,
        "File created": SYSMON_FILE_CREATE,
        "Registry object added or deleted": SYSMON_REGISTRY_CREATE,
        "Registry key created": SYSMON_REGISTRY_CREATE,
        "Registry value set": SYSMON_REGISTRY_SET,
        "Registry key renamed": SYSMON_REGISTRY_RENAME,
        "Dns query": SYSMON_DNS_QUERY,
        "DNS query": SYSMON_DNS_QUERY,
        "File Delete archived": SYSMON_FILE_DELETE,
        "File deleted": SYSMON_FILE_DELETE_DETECTED,
        "Clipboard changed": SYSMON_CLIPBOARD_CHANGE,
        "Process tampering": SYSMON_PROCESS_TAMPERING,
    }

    def _parse_msg(msg):
        if not msg or not isinstance(msg, str):
            return "", {}
        parts = msg.replace("\r\n", "\n").split("\n")
        header = parts[0].rstrip(":").strip() if parts else ""
        fields = {}
        for line in parts[1:]:
            m = re.match(r"^([A-Za-z][A-Za-z0-9_]*):\s*(.*)$", line)
            if m:
                fields[m.group(1)] = m.group(2).strip()
        return header, fields

    relevant_guids, relevant_pids, root_count, id_mode = _build_sample_process_tree(
        data, sample_names, sample_hashes
    )
    if root_count == 0:
        log.warning(
            "sysmon filter: no process-create matched the sample "
            "(names=%s hashes=%s). Emitting all events unchanged.",
            sorted(sample_names)[:3], sorted(sample_hashes)[:1],
        )
    else:
        log.info(
            "sysmon filter: %d events, %d roots (mode=%s), %d guids / %d pids",
            len(data), root_count, id_mode, len(relevant_guids), len(relevant_pids),
        )
    emitted_by_sample = 0
    skipped_as_noise = 0


    for i, ev in enumerate(data):
        if not isinstance(ev, dict):
            continue

        eid = ev.get("Id") or ev.get("EventID")
        header, msg_fields = _parse_msg(ev.get("Message", ""))

        if eid is None and header:
            for h_key, h_eid in HEADER_TO_EID.items():
                if header.startswith(h_key):
                    eid = h_eid
                    break

        if eid is None:
            if header:
                _ts_raw = ev.get("TimeCreated")
                _ts = _parse_cuckoo_date(_ts_raw) or (str(_ts_raw) if _ts_raw else "unknown")
                b.add("event", "sysmon_unrecognized", header, header, rel, sha,
                      f"event[{i}] unrecognized header '{header}' @ {_ts}")
            continue

        if root_count > 0:
            check_guids = set()
            check_pids = set()
            for fname in ("ProcessGuid", "SourceProcessGuid", "TargetProcessGuid"):
                v = msg_fields.get(fname, "").strip()
                if v:
                    check_guids.add(v)
            for fname in ("ProcessId", "SourceProcessId", "TargetProcessId"):
                v = msg_fields.get(fname, "").strip()
                if v:
                    try:
                        check_pids.add(int(v))
                    except ValueError:
                        pass
            if check_guids or check_pids:
                in_tree = (
                    (check_guids and (check_guids & relevant_guids))
                    or (check_pids and (check_pids & relevant_pids))
                )
                if not in_tree:
                    skipped_as_noise += 1
                    continue
                emitted_by_sample += 1
            else:
                # Event type carries no process attribution (e.g. Linux EID 3).
                # Keep; agent-side _drop_id3 already scoped it.
                emitted_by_sample += 1


        props = ev.get("Properties", []) or []
        vals = [(p.get("Value") if isinstance(p, dict) else "") or "" for p in props]
        _ts_raw = ev.get("TimeCreated")
        ts = _parse_cuckoo_date(_ts_raw) or (str(_ts_raw) if _ts_raw else "unknown")
        emitted = False

        def _get(key, pos=None, *aliases):
            for k in (key,) + aliases:
                v = msg_fields.get(k)
                if v is not None and v != "-" and v != "":
                    return v
            if pos is not None and pos < len(vals):
                v2 = vals[pos]
                if v2 and v2 != "-":
                    return v2
            return ""

        def _f(category, key_name, value, locator_extra):
            nonlocal emitted
            if not value or value == "-":
                return
            b.add(category, key_name, value, str(value), rel, sha,
                  f"event[{i}] EventID {eid} {locator_extra} @ {ts}")
            emitted = True

        if eid == SYSMON_PROCESS_CREATE:
            _f("process", "image", _get("Image", 4, "ProcessName", "Exe", "Comm"), "Image")
            _f("process", "command_line", _get("CommandLine", 5, "Cmdline", "Cmd"), "CommandLine")
            _f("file", "cwd", _get("CurrentDirectory", 6, "Cwd"), "CurrentDirectory")
            _f("user", "user", _get("User", 7), "User")
            _f("process", "parent_image", _get("ParentImage", 15, "ParentProcessName"), "ParentImage")
            _f("process", "parent_command_line", _get("ParentCommandLine", 16), "ParentCommandLine")

        elif eid == SYSMON_NETWORK_CONNECT:
            image = _get("Image", 4, "ProcessName", "Exe", "Comm")
            proto = _get("Protocol", 6)
            src_ip = _get("SourceIp", 9, "SrcIp", "SourceIP")
            dst_ip = _get("DestinationIp", 14, "DstIp", "DestIp", "DestinationIP")
            dst_host = _get("DestinationHostname", 15, "DstHostname", "DestHostname")
            dst_port = _get("DestinationPort", 16, "DstPort", "DestPort")
            target = ""
            if dst_ip and dst_port and proto:
                target = f"{dst_ip}:{dst_port}/{proto}"
            elif dst_ip and proto:
                target = f"{dst_ip}/{proto}"
            elif dst_ip:
                target = dst_ip
            elif dst_host:
                target = dst_host
            if target and dst_host and dst_host != "-" and dst_ip:
                target = f"{dst_host} ({dst_ip}:{dst_port}/{proto})"
            if target:
                b.add("network", "sysmon_connect", target, target, rel, sha,
                      f"event[{i}] EventID {eid} {image} -> {target} @ {ts}")
                emitted = True
            if src_ip and src_ip != "0.0.0.0":
                _f("network", "source_ip", src_ip, "SourceIp")
            if image:
                _f("process", "network_image", image, "Image")

        elif eid == SYSMON_PROCESS_TERMINATE:
            _f("process", "terminated_image", _get("Image", 4, "ProcessName"), "Image")

        elif eid == SYSMON_FILE_CREATE:
            _f("file", "created", _get("TargetFilename", 5, "FileName", "FilePath"), "TargetFilename")
            _f("process", "creator_image", _get("Image", 4, "ProcessName"), "Image")
            _f("user", "user", _get("User", 7), "User")

        elif eid == SYSMON_FILE_DELETE or eid == SYSMON_FILE_DELETE_DETECTED:
            _f("file", "deleted", _get("TargetFilename", 6, "FileName", "FilePath"), "TargetFilename")
            _f("process", "deleter_image", _get("Image", 5, "ProcessName"), "Image")

        elif eid == SYSMON_DNS_QUERY:
            qname = _get("QueryName", 4)
            if qname and not qname.endswith(('.arpa', '.arpa.', '.local', '.local.')):
                _f("dns", "query", qname, "QueryName")
                _f("dns", "query_results", _get("QueryResults", 6), "QueryResults")
                _f("process", "dns_image", _get("Image", 7, "ProcessName"), "Image")

        elif eid == SYSMON_IMAGE_LOAD:
            _loader = _get("Image", 4, "ProcessName")
            _loaded = _get("ImageLoaded", 5, "LoadedImage")
            _signed = _get("Signed", 10)
            if _loader and _loaded:
                if _signed and _signed.lower() == "true":
                    _f("process", "image_load",
                       f"{_loader} loaded {_loaded} (signed)", "ImageLoad")
                elif _signed:
                    _f("process", "image_load",
                       f"{_loader} loaded {_loaded} (unsigned)", "ImageLoad")
                else:
                    _f("process", "image_load",
                       f"{_loader} loaded {_loaded}", "ImageLoad")
            else:
                _f("process", "image_loaded", _loaded, "ImageLoaded")

        elif eid == SYSMON_PROCESS_ACCESS:
            _src = _get("SourceImage", 5, "SourceProcessName")
            _tgt = _get("TargetImage", 8, "TargetProcessName")
            _acc = _get("GrantedAccess", 9)
            if _src and _tgt:
                _f("process", "process_access",
                   f"{_src} -> {_tgt} [{_acc or '?'}]", "ProcessAccess")
            else:
                _f("process", "access_source_image", _src, "SourceImage")
                _f("process", "access_target_image", _tgt, "TargetImage")
                _f("process", "access_granted", _acc, "GrantedAccess")

        elif eid == SYSMON_CREATE_REMOTE_THREAD:
            _f("process", "remote_thread_source", _get("SourceImage", 4), "SourceImage")
            _f("process", "remote_thread_target", _get("TargetImage", 7), "TargetImage")
            _f("process", "remote_thread_start_address", _get("StartAddress", 9), "StartAddress")
            _f("process", "remote_thread_start_module", _get("StartModule", 10), "StartModule")

        elif eid == SYSMON_REGISTRY_CREATE:
            _f("registry", "key_created", _get("TargetObject", 6, "RegistryKey", "Key"), "TargetObject")
            _f("process", "registry_writer", _get("Image", 5, "ProcessName"), "Image")

        elif eid == SYSMON_REGISTRY_SET:
            _f("registry", "value_set", _get("TargetObject", 6, "RegistryKey", "Key"), "TargetObject")
            _f("registry", "value_data", _get("Details", 7, "Value", "Data"), "Details")
            _f("process", "registry_writer", _get("Image", 5, "ProcessName"), "Image")

        elif eid == SYSMON_REGISTRY_RENAME:
            _f("registry", "key_renamed_from", _get("TargetObject", 6, "RegistryKey", "Key"), "TargetObject")
            _f("registry", "key_renamed_to", _get("NewName", 7), "NewName")
            _f("process", "registry_writer", _get("Image", 5, "ProcessName"), "Image")

        elif eid == SYSMON_CLIPBOARD_CHANGE:
            _f("event", "clipboard_changed_by", _get("Image", 4, "ProcessName"), "Image")
            _f("event", "clipboard_content_hash", _get("Hashes", 6, "Hash"), "Hashes")

        elif eid == SYSMON_PROCESS_TAMPERING:
            _f("process", "tampered_image", _get("Image", 4, "ProcessName"), "Image")
            _f("process", "tampering_type", _get("Type", 5), "Type")

        if not emitted and header:
            b.add("event", "sysmon_event_occurred", header, header, rel, sha,
                  f"event[{i}] EventID {eid} {header} @ {ts}")
    if root_count > 0:
        log.info(
            "sysmon filter result (mode=%s): %d events kept (in-tree), "
            "%d skipped (noise), %d facts emitted total",
            id_mode, emitted_by_sample, skipped_as_noise, len(b.facts),
        )
        b.add(
            "metadata", "sysmon_scope",
            f"{emitted_by_sample}/{len(data)} events related to sample",
            f"{emitted_by_sample}/{len(data)} events related to sample, "
            f"{root_count} root process(es), {len(relevant_guids)} guid(s) / "
            f"{len(relevant_pids)} pid(s)",
            "sysmon.json", b.sha256_of(task_dir / "sysmon.json"),
            "scope_filter_summary",
        )


    return {}, True


def _extract_pcap(task_dir: Path, b: _Builder, artifacts: list) -> dict:
    path = task_dir / "dump.pcap"
    rel = f"{task_dir.name}/dump.pcap"
    summary = {
        "present": path.is_file(),
        "packet_count": 0,
        "flows": [],
        "dns_queries": [],
        "http_requests": [],
        "tls_sessions": [],
        "parse_error": None,
    }
    if not path.is_file():
        artifacts.append(_file_artifact_entry("dump.pcap", rel, path, "absent"))
        return summary
    artifacts.append(_file_artifact_entry("dump.pcap", rel, path, "parsed"))
    sha = b.sha256_of(path)
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR
    except Exception as exc:
        summary["parse_error"] = f"scapy_import_error:{exc}"
        return summary
    try:
        packets = rdpcap(str(path))
    except Exception as exc:
        summary["parse_error"] = f"read_error:{exc}"
        return summary
    summary["packet_count"] = len(packets)
    seen_flows: dict[tuple, int] = {}   # (src,sport,dst,dport,proto) -> first packet index
    for i, pkt in enumerate(packets):
        try:
            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer is None:
                continue
            src = str(getattr(ip_layer, "src", ""))
            dst = str(getattr(ip_layer, "dst", ""))
            try:
                if ipaddress.ip_address(dst).is_multicast:
                    continue  # Skip mDNS/SSDP broadcast noise
            except ValueError:
                pass
            proto = "ipv4" if pkt.haslayer(IP) else "ipv6"
            sport = dport = None
            if pkt.haslayer(TCP):
                sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
                proto = "tcp"
            elif pkt.haslayer(UDP):
                sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
                proto = "udp"
            flow = f"{src}:{sport} -> {dst}:{dport}/{proto}" if sport else f"{src} -> {dst}/{proto}"
            flow_key = (src, sport, dst, dport, proto)
            if flow_key in seen_flows:
                continue   # already emitted this flow; skip duplicate
            seen_flows[flow_key] = i
            summary["flows"].append({"src_ip": src, "dst_ip": dst,
                                    "src_port": sport, "dst_port": dport,
                                    "protocol": proto, "packet_index": i})
            b.add("network", "pcap_flow", flow, flow, rel, sha,
                  f"packet[{i}] (first of flow)", authoritative=True)
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if getattr(dns, "qr", 0) == 0 and dns.qd is not None:
                    for q in dns.qd:
                        if isinstance(q, DNSQR):
                            qname = q.qname.decode(errors="replace") if isinstance(q.qname, bytes) else str(q.qname)
                            if not qname.endswith(('.arpa', '.arpa.', '.local', '.local.')):
                                summary["dns_queries"].append({"name": qname, "type": str(q.qtype)})
                                b.add("dns", "pcap_query", qname, qname, rel, sha, f"packet[{i}] dns_query", authoritative=True)
                elif getattr(dns, "qr", 0) == 1 and dns.an is not None:
                    an = dns.an
                    depth = 0
                    while an is not None and depth < 8:
                        if isinstance(an, DNSRR):
                            rrname = an.rrname.decode(errors="replace") if isinstance(an.rrname, bytes) else str(an.rrname)
                            rdata = an.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode(errors="replace")
                            b.add("dns", "pcap_response", f"{rrname} -> {rdata}", f"{rrname} -> {rdata}", rel, sha, f"packet[{i}] dns_response", authoritative=True)
                            an = an.payload if hasattr(an, "payload") and isinstance(getattr(an, "payload", None), DNSRR) else None
                        else:
                            break
                        depth += 1
        except Exception as exc:
            log.warning("pcap packet[%d] parse error: %s", i, exc)
    return summary


def _extract_machine(task_dir: Path, b: _Builder, artifacts: list) -> dict:
    path = task_dir / "machine.json"
    rel = f"{task_dir.name}/machine.json"
    data, err = _load_json(path)
    if data is None:
        artifacts.append(_file_artifact_entry("machine.json", rel, path, err or "absent", err))
        return {}
    artifacts.append(_file_artifact_entry("machine.json", rel, path, "parsed"))
    sha = b.sha256_of(path)
    for key, field in [
        ("sandbox_machine_name", "name"),
        ("sandbox_machine_label", "label"),
        ("sandbox_platform", "platform"),
        ("sandbox_os_version", "os_version"),
        ("sandbox_architecture", "architecture"),
        ("sandbox_machinery", "machinery_name"),
    ]:
        v = data.get(field)
        if v:
            b.add("metadata", key, v, str(v), rel, sha, field)
    ip = data.get("ip")
    if ip:
        b.add("network", "sandbox_ip", ip, ip, rel, sha, "ip")
    return data


def _extract_payload_log(task_dir: Path, b: _Builder, artifacts: list) -> None:
    path = task_dir / "payload.log"
    rel = f"{task_dir.name}/payload.log"
    if not path.is_file():
        artifacts.append(_file_artifact_entry("payload.log", rel, path, "absent"))
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except Exception as exc:
        artifacts.append(_file_artifact_entry("payload.log", rel, path, "parse_error", str(exc)))
        return
    artifacts.append(_file_artifact_entry("payload.log", rel, path, "parsed" if text else "empty"))
    if not text:
        return
    sha = b.sha256_of(path)
    b.add("process", "payload_log", text, text[:400], rel, sha, "whole_file")


def _extract_report(task_dir: Path, b: _Builder, artifacts: list) -> dict:
    path = task_dir / "report.json"
    rel = f"{task_dir.name}/report.json"
    data, err = _load_json(path)
    if data is None:
        artifacts.append(_file_artifact_entry("report.json", rel, path, err or "absent", err))
        return {}
    artifacts.append(_file_artifact_entry("report.json", rel, path, "parsed"))
    sha = b.sha256_of(path)
    if isinstance(data, dict):
        score = data.get("score")
        if score is not None:
            b.add("metadata", "report_score", score, str(score), rel, sha, "score")
        for sig in data.get("signatures", []) or []:
            name = sig if isinstance(sig, str) else sig.get("name")
            if name:
                b.add("metadata", "report_signature", name, str(name), rel, sha, "signatures")
        for ttp in data.get("ttps", []) or []:
            b.add("metadata", "report_ttp", str(ttp), str(ttp), rel, sha, "ttps")
    return data


def _extract_binary(analysis_dir: Path, b: _Builder, artifacts: list, insufficient: list) -> dict:
    symlink = analysis_dir / "binary"
    bin_info = {
        "sha256": "0" * 64,
        "size_bytes": 0,
        "realpath_resolved": True,
        "file_type": "unknown",
        "link_present": symlink.is_symlink(),
    }
    if not symlink.exists() and not symlink.is_symlink():
        insufficient.append({"section": "binary", "reason": "binary symlink absent", "required_artifact": "binary"})
        return bin_info
    try:
        real = symlink.resolve(strict=True)
    except Exception:
        insufficient.append({"section": "binary", "reason": "symlink target missing on this host", "required_artifact": "binary"})
        return bin_info
    if not real.is_file():
        insufficient.append({"section": "binary", "reason": "resolved target is not a regular file", "required_artifact": "binary"})
        return bin_info
    sha = _sha256_file(real)
    file_type = "unknown"
    try:
        with real.open("rb") as f:
            head = f.read(4)
        if head[:2] == b"MZ":
            file_type = "PE"
        elif head[:4] == b"\x7fELF":
            file_type = "ELF"
    except Exception:
        pass
    bin_info.update({"sha256": sha, "size_bytes": real.stat().st_size, "file_type": file_type, "link_present": True})
    b.add("metadata", "binary_sha256", sha, sha, "binary", sha, "realpath_target", authoritative=True)
    b.add("metadata", "binary_file_type", file_type, file_type, "binary", sha, "realpath_target", authoritative=True)
    return bin_info


def _select_richest_task(task_dirs: list[Path]) -> tuple[Path, str, list[dict]]:
    if not task_dirs:
        raise ValueError("no task_N directories found")
    if len(task_dirs) == 1:
        return task_dirs[0], "only one task dir present", []
    scored = []
    for td in task_dirs:
        size = sum(f.stat().st_size for f in td.rglob("*") if f.is_file())
        has_sysmon = (td / "sysmon.json").is_file()
        has_pcap = (td / "dump.pcap").is_file()
        score = size + (1_000_000 if has_sysmon else 0) + (500_000 if has_pcap else 0)
        scored.append((score, td, size, has_sysmon, has_pcap))
    scored.sort(key=lambda x: (-x[0], x[1].name))
    chosen = scored[0]
    others = []
    for s, td, sz, sy, pc in scored[1:]:
        others.append({
            "task_dir": td.name,
            "artifact_presence": {
                "sysmon.json": sy,
                "dump.pcap": pc,
                "report.json": (td / "report.json").is_file(),
            },
            "fact_count": 0,
            "reason_not_selected": f"smaller than {chosen[1].name} ({sz} bytes vs {chosen[2]} bytes)",
        })
    return chosen[1], f"selected largest task {chosen[1].name} ({chosen[2]} bytes)", others


def _derive_analysis_date(analysis_dir: Path, analysis_data: dict) -> str | None:
    parent = analysis_dir.parent.name
    if re.fullmatch(r"\d{8}", parent):
        return parent
    created = analysis_data.get("created_on") if isinstance(analysis_data, dict) else None
    if isinstance(created, dict) and "__isodt__" in created:
        try:
            dt = datetime.fromisoformat(created["__isodt__"])
            return dt.strftime("%Y%m%d")
        except Exception:
            pass
    return None


def extract(
    analysis_dir: Path,
    submission_id: str,
    cuckoo_task_id: str,
    analysis_date: str | None = None,
) -> dict:
    """Extract an evidence bundle dict from a Cuckoo analysis directory."""
    if not analysis_dir.is_dir():
        raise FileNotFoundError(f"analysis dir not found: {analysis_dir}")

    artifacts: list[dict] = []
    insufficient: list[dict] = []
    warnings: list[str] = []

    task_dirs = sorted([d for d in analysis_dir.iterdir() if d.is_dir() and d.name.startswith("task_")])
    if not task_dirs:
        raise ValueError(f"no task_N directories in {analysis_dir}")
    selected_task, selection_reason, additional_tasks = _select_richest_task(task_dirs)

    # Extract analysis metadata FIRST so analysis_data is available for the
    # analysis_date fallback below.
    builder = _Builder()
    analysis_data = _extract_analysis_metadata(analysis_dir, builder, artifacts)

    if analysis_date is None:
        analysis_date = _derive_analysis_date(analysis_dir, analysis_data)
    if not analysis_date:
        raise ValueError(
            f"cannot derive analysis_date from parent dir '{analysis_dir.parent.name}' "
            f"or analysis.json created_on; pass analysis_date explicitly"
        )

    _extract_filetree(analysis_dir, builder, artifacts)
    _extract_pre_static(analysis_dir, builder, artifacts)
    _extract_task_metadata(selected_task, builder, artifacts)
    _extract_agent_analysis(selected_task, builder, artifacts)
    _tgt = (analysis_data.get("target", {}) or {}) if isinstance(analysis_data, dict) else {}
    _sub = (analysis_data.get("submitted", {}) or {}) if isinstance(analysis_data, dict) else {}
    sample_names = set()
    for k in ("filename", "orig_filename"):
        v = _tgt.get(k)
        if isinstance(v, str) and v:
            sample_names.add(v.lower())
            sample_names.add(v.replace("/", "\\").split("\\")[-1].lower())
    sample_hashes = set()
    for k in ("md5", "sha1", "sha256", "sha512"):
        v = _tgt.get(k) or _sub.get(k)
        if isinstance(v, str) and len(v) >= 16:
            sample_hashes.add(v.lower())
    _, sysmon_present = _extract_sysmon(
        selected_task, builder, artifacts, sample_names, sample_hashes
    )
    if not sysmon_present:
        insufficient.append({"section": "process_events", "reason": "sysmon.json absent; no process creation telemetry available", "required_artifact": "sysmon.json"})
        insufficient.append({"section": "file_events", "reason": "sysmon.json absent; no file creation telemetry available", "required_artifact": "sysmon.json"})
        insufficient.append({"section": "sysmon_network_events", "reason": "sysmon.json absent; sysmon network telemetry unavailable (pcap still authoritative)", "required_artifact": "sysmon.json"})
    pcap_summary = _extract_pcap(selected_task, builder, artifacts)
    if not pcap_summary["present"]:
        insufficient.append({"section": "network_events", "reason": "dump.pcap absent; no authoritative network telemetry available", "required_artifact": "dump.pcap"})
    _extract_machine(selected_task, builder, artifacts)
    _extract_payload_log(selected_task, builder, artifacts)
    _extract_report(selected_task, builder, artifacts)
    binary_info = _extract_binary(analysis_dir, builder, artifacts, insufficient)

    bundle = {
        "schema_version": "evidence-bundle/1.0",
        "submission_id": submission_id,
        "cuckoo_task_id": cuckoo_task_id,
        "analysis_date": analysis_date,
        "extracted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "extractor_version": EXTRACTOR_VERSION,
        "sanitization_manifest_id": None,
        "task_selection": {
            "policy": "single_task" if len(task_dirs) == 1 else "select_richest_task",
            "selected_task_dir": selected_task.name,
            "reason": selection_reason,
            "additional_tasks": additional_tasks,
        },
        "artifacts": artifacts,
        "binary": binary_info,
        "facts": builder.facts,
        "pcap_summary": pcap_summary,
        "screenshots": [],
        "absent_artifacts": [
            {"relative_path": a["relative_path"], "reason": a["parser_status"]}
            for a in artifacts
            if not a["present"]
        ],
        "insufficient_evidence": insufficient,
        "extraction_warnings": warnings,
    }
    shot_dir = selected_task / "screenshots"
    if shot_dir.is_dir():
        for shot in sorted(shot_dir.iterdir()):
            if shot.is_file() and shot.suffix.lower() in (".png", ".jpg", ".jpeg"):
                bundle["screenshots"].append({
                    "relative_path": f"{selected_task.name}/screenshots/{shot.name}",
                    "sha256": _sha256_file(shot),
                    "width": None,
                    "height": None,
                    "captured_at": None,
                })
    return bundle
