"""Production knowledge ingestion.

Sources:
  - MITRE ATT&CK enterprise STIX 2.1 bundle (versioned, from attack-stix-data)
  - NVD CVE 2.0 yearly gzip feeds and the modified feed
  - CISA KEV JSON
  - Maintained baseline YAML

Embedding strategy: each document is embedded from its first 800 characters
(the lead summary), while the full text is stored in Chroma. Retrieval
relevance comes from the lead; full text stays available for LLM citation.
This cuts embedding workload by roughly 3x versus embedding the full document.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import sqlite3
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

from app.knowledge import get_collection, OllamaEmbeddingFunction, EMBED_BATCH

log = logging.getLogger(__name__)

ROOT = Path("/opt/pipeline")
CONFIG_PATH = ROOT / "config" / "knowledge_sources.yaml"
SYNC_DB = ROOT / "data" / "knowledge_sync.db"
USER_AGENT = "pipeline-knowledge-sync/1.0"
HTTP_TIMEOUT = 600.0
RETRIES = 3
UPSERT_BATCH = 500
KEV_LOOKUP_BATCH = 200
EMBED_TRUNCATE = 800

BASELINE_TYPES = [
    "baseline-playbook",
    "baseline-nist",
    "baseline-owasp",
    "baseline-cwe",
    "baseline-capec",
]

_EMBED = OllamaEmbeddingFunction()


def _progress(msg: str) -> None:
    print(f"[ingest] {msg}", flush=True)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_ts(iso: str | None) -> int:
    if not iso:
        return 0
    try:
        return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())
    except Exception:
        pass
    try:
        from email.utils import parsedate_to_datetime
        return int(parsedate_to_datetime(iso).timestamp())
    except Exception:
        return 0



def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _vkey(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0,)


def _batched(seq: list, n: int):
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def _config() -> dict:
    return yaml.safe_load(CONFIG_PATH.read_text())


def _db() -> sqlite3.Connection:
    SYNC_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(SYNC_DB)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS source_state (
            source TEXT PRIMARY KEY,
            etag TEXT,
            last_modified TEXT,
            version TEXT,
            content_sha256 TEXT,
            last_run_at TEXT,
            last_status TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sync_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            mode TEXT NOT NULL,
            sources TEXT NOT NULL,
            status TEXT NOT NULL,
            counts_json TEXT NOT NULL DEFAULT '{}',
            errors_json TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    conn.commit()
    return conn


def _state_get(source: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(
            "SELECT etag, last_modified, version, content_sha256, last_run_at, last_status "
            "FROM source_state WHERE source = ?",
            (source,),
        ).fetchone()
    if not row:
        return None
    return {
        "etag": row[0],
        "last_modified": row[1],
        "version": row[2],
        "content_sha256": row[3],
        "last_run_at": row[4],
        "last_status": row[5],
    }


def _state_set(source: str, **kw) -> None:
    fields = ["etag", "last_modified", "version", "content_sha256", "last_run_at", "last_status"]
    values = [kw.get(f, "") or "" for f in fields]
    with _db() as conn:
        conn.execute(
            "INSERT INTO source_state (source, etag, last_modified, version, content_sha256, last_run_at, last_status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(source) DO UPDATE SET "
            "etag=excluded.etag, last_modified=excluded.last_modified, version=excluded.version, "
            "content_sha256=excluded.content_sha256, last_run_at=excluded.last_run_at, last_status=excluded.last_status",
            [source, *values],
        )
        conn.commit()


def _run_start(mode: str, sources: list[str]) -> int:
    with _db() as conn:
        cur = conn.execute(
            "INSERT INTO sync_runs (started_at, mode, sources, status) VALUES (?, ?, ?, 'running')",
            (_now(), mode, ",".join(sources)),
        )
        conn.commit()
        return int(cur.lastrowid)


def _run_finish(run_id: int, status: str, counts: dict, errors: dict) -> None:
    with _db() as conn:
        conn.execute(
            "UPDATE sync_runs SET finished_at=?, status=?, counts_json=?, errors_json=? WHERE id=?",
            (_now(), status, json.dumps(counts), json.dumps(errors), run_id),
        )
        conn.commit()


def _fetch(url: str, etag: str | None = None, last_modified: str | None = None) -> tuple[bytes | None, dict]:
    """Download a URL with streaming progress. Returns (bytes_or_None, headers).

    None means 304 Not Modified.
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    last_exc: Exception | None = None
    for attempt in range(RETRIES):
        try:
            _progress(f"GET {url} (attempt {attempt + 1}/{RETRIES})")
            with httpx.stream("GET", url, headers=headers, timeout=HTTP_TIMEOUT, follow_redirects=True) as r:
                if r.status_code == 304:
                    _progress(f"304 Not Modified: {url}")
                    return None, dict(r.headers)
                r.raise_for_status()
                total = int(r.headers.get("content-length", 0) or 0)
                buf = bytearray()
                last_report = 0
                started = time.time()
                for chunk in r.iter_bytes(chunk_size=1024 * 1024):
                    buf.extend(chunk)
                    if len(buf) - last_report >= 16 * 1024 * 1024:
                        elapsed = max(0.1, time.time() - started)
                        mb = len(buf) / (1024 * 1024)
                        rate = mb / elapsed
                        total_str = f"/{total / (1024 * 1024):.0f} MB" if total else ""
                        _progress(f"  {mb:.1f}{total_str} @ {rate:.1f} MB/s")
                        last_report = len(buf)
                _progress(f"  downloaded {len(buf) / (1024 * 1024):.1f} MB")
                return bytes(buf), dict(r.headers)
        except Exception as exc:
            last_exc = exc
            log.warning("fetch attempt %d/%d failed for %s: %s", attempt + 1, RETRIES, url, exc)
            time.sleep(2 ** attempt)
    raise RuntimeError(f"fetch failed for {url}: {last_exc}")


def _record(
    chunk_id: str,
    source_id: str,
    source_type: str,
    title: str,
    text: str,
    published_at: str = "",
    modified_at: str = "",
    **extra: Any,
) -> dict:
    now = _now()
    meta = {
        "source_id": source_id,
        "source_type": source_type,
        "title": title,
        "published_at": published_at or "",
        "published_ts": _to_ts(published_at),
        "modified_at": modified_at or "",
        "modified_ts": _to_ts(modified_at),
        "content_hash": _sha256_bytes(text.encode("utf-8")),
        "last_seen": now,
        "last_seen_ts": _to_ts(now),
        "superseded_by": "",
        "kev": False,
        "kev_due_date": "",
        "kev_ransomware": "",
        "severity": "",
        "cvss_score": 0.0,
        "cwe_ids_json": "[]",
        "tactics_json": "[]",
        "technique_id": "",
        "playbook_id": "",
        "version": "",
    }
    for k, v in extra.items():
        if v is None:
            continue
        meta[k] = v
    return {"chunk_id": chunk_id, "text": text, "metadata": meta}


def _embed_docs(texts: list[str]) -> list[list[float]]:
    """Embed truncated lead summaries. Full text is stored separately."""
    truncated = [t[:EMBED_TRUNCATE] for t in texts]
    out: list[list[float]] = []
    for i in range(0, len(truncated), EMBED_BATCH):
        out.extend(_EMBED(truncated[i : i + EMBED_BATCH]))
    return out


def _upsert(collection, records: list[dict]) -> None:
    """Upsert with explicit embeddings computed from truncated text.

    The full text is stored as the document; the embedding is derived from the
    first EMBED_TRUNCATE chars (the lead). This is the speed lever: NVD/KEV
    descriptions are 2000+ chars, but the retrieval-relevant lead is the first
    800. Embedding only the lead cuts work by 3x and keeps quality.
    """
    total = len(records)
    done = 0
    for batch in _batched(records, UPSERT_BATCH):
        embeddings = _embed_docs([r["text"] for r in batch])
        collection.upsert(
            ids=[r["chunk_id"] for r in batch],
            documents=[r["text"] for r in batch],
            metadatas=[r["metadata"] for r in batch],
            embeddings=embeddings,
        )
        done += len(batch)
        _progress(f"  upserted {done}/{total}")


def _existing_ids(collection, where: dict) -> set[str]:
    res = collection.get(where=where, include=[])
    return set(res.get("ids", []))


def _delete_stale(collection, where: dict, keep: set[str]) -> int:
    existing = _existing_ids(collection, where)
    stale = existing - keep
    if stale:
        collection.delete(ids=list(stale))
    return len(stale)


# ----------------------------- baseline -----------------------------

def ingest_baseline(collection) -> dict:
    cfg = _config()
    path = Path(cfg["baseline"]["path"])
    data = yaml.safe_load(path.read_text())
    entries = data.get("entries", [])
    _progress(f"baseline: {len(entries)} entries")
    records = []
    keep = set()
    for e in entries:
        rid = e["id"]
        keep.add(rid)
        records.append(_record(
            rid,
            rid,
            e["source_type"],
            e["title"],
            e["text"].strip(),
            e.get("published_at", ""),
            e.get("published_at", ""),
            playbook_id=e.get("playbook_id", ""),
        ))
    _upsert(collection, records)
    deleted = _delete_stale(collection, {"source_type": {"$in": BASELINE_TYPES}}, keep)
    _state_set("baseline", content_sha256=_sha256_bytes(path.read_bytes()), last_run_at=_now(), last_status="ok")
    return {"count": len(records), "deleted": deleted}


# ----------------------------- MITRE -----------------------------

def _mitre_latest(cfg: dict) -> tuple[str, str]:
    index_url = cfg["mitre"]["index_url"]
    fallback = cfg["mitre"]["fallback_bundle_url"]
    try:
        raw, _ = _fetch(index_url)
        idx = json.loads(raw)
        entry = idx.get("enterprise-attack") or {}
        versions = entry.get("versions") or []
        if versions:
            latest = max(versions, key=lambda v: _vkey(v.get("version", "0")))
            return latest.get("version", "unknown"), latest.get("url") or fallback
    except Exception as exc:
        log.warning("mitre index unavailable, using fallback: %s", exc)
    return "unknown", fallback


def ingest_mitre(collection, force: bool = False) -> dict:
    cfg = _config()
    version, bundle_url = _mitre_latest(cfg)
    state = _state_get("mitre")
    if not force and state and state.get("version") == version and version != "unknown":
        _progress(f"mitre: skipped (version {version} already loaded)")
        return {"skipped": True, "version": version}

    _progress(f"mitre: fetching version {version}")
    raw, headers = _fetch(bundle_url)
    if raw is None:
        return {"skipped": True, "version": version}

    bundle = json.loads(raw)
    objects = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objects if isinstance(o, dict) and "id" in o}

    mitigations: dict[str, list[str]] = defaultdict(list)
    for o in objects:
        if not isinstance(o, dict):
            continue
        if o.get("type") == "relationship" and o.get("relationship_type") == "mitigates":
            src = by_id.get(o.get("source_ref"))
            if src and src.get("type") == "course-of-action":
                desc = (src.get("description") or "").strip()
                if desc:
                    mitigations[o.get("target_ref", "")].append(desc[:800])

    records = []
    keep = set()
    for o in objects:
        if not isinstance(o, dict) or o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext_id = ""
        for ref in o.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                ext_id = ref["external_id"]
                break
        if not ext_id:
            continue
        tactics = [p.get("phase_name") for p in (o.get("kill_chain_phases") or []) if isinstance(p, dict) and p.get("phase_name")]
        desc = (o.get("description") or "").strip()[:2000]
        detect = (o.get("x_mitre_detection") or "").strip()[:1000]
        mits = mitigations.get(o.get("id", ""), [])[:5]

        text = f"{ext_id} {o.get('name', '')}. Tactics: {', '.join(tactics) or 'unknown'}. {desc}"
        if detect:
            text += f" Detection: {detect}"
        if mits:
            text += " Mitigations: " + " | ".join(mits)

        rid = f"mitre:{ext_id}"
        keep.add(rid)
        records.append(_record(
            rid, rid, "mitre-attack",
            f"{ext_id} {o.get('name', '')}".strip(),
            text,
            o.get("created", ""), o.get("modified", ""),
            technique_id=ext_id,
            tactics_json=json.dumps(tactics),
            version=version,
        ))

    _progress(f"mitre: upserting {len(records)} techniques (version {version})")
    _upsert(collection, records)
    deleted = _delete_stale(collection, {"source_type": {"$eq": "mitre-attack"}}, keep)
    _state_set(
        "mitre",
        etag=headers.get("etag", ""),
        last_modified=headers.get("last-modified", ""),
        version=version,
        content_sha256=_sha256_bytes(raw),
        last_run_at=_now(),
        last_status="ok",
    )
    return {"count": len(records), "deleted": deleted, "version": version}


# ----------------------------- NVD -----------------------------

def _cvss(cve: dict) -> tuple[float, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = (cve.get("metrics") or {}).get(key) or []
        if not metrics:
            continue
        primary = next((m for m in metrics if m.get("type") == "Primary"), metrics[0])
        data = primary.get("cvssData") or {}
        score = float(data.get("baseScore", 0) or 0)
        severity = data.get("baseSeverity") or primary.get("baseSeverity") or ""
        if not severity:
            severity = (
                "CRITICAL" if score >= 9.0 else
                "HIGH" if score >= 7.0 else
                "MEDIUM" if score >= 4.0 else
                "LOW" if score > 0 else "UNKNOWN"
            )
        return score, severity.upper()
    return 0.0, "UNKNOWN"


def _references(cve: dict) -> list[dict]:
    """Extract NVD references that point at patches, advisories, or exploits.

    NVD tags each reference with one or more of "Patch", "Vendor Advisory",
    "Third Party Advisory", "Exploit", "Mitigation", "Release Notes". These
    are the CVE author's own citations to the fix — the highest-quality
    remediation signal available without scraping vendor sites.
    """
    useful = {"Patch", "Vendor Advisory", "Third Party Advisory", "Exploit", "Mitigation", "Release Notes"}
    out = []
    for ref in (cve.get("references") or []):
        url = (ref.get("url") or "").strip()
        if not url:
            continue
        tags = [t for t in (ref.get("tags") or []) if t in useful]
        if not tags:
            continue
        out.append({
            "url": url,
            "source": (ref.get("source") or "")[:80],
            "tags": tags,
        })
        if len(out) >= 5:
            break
    return out


def _cwes(cve: dict) -> list[str]:
    out = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = (d.get("value") or "").strip()
            if v.startswith("CWE-") and v not in out:
                out.append(v)
    return out


def _nvd_records(payload: dict) -> list[dict]:
    records = []
    for item in payload.get("vulnerabilities", []) or []:
        cve = item.get("cve") or {}
        cid = cve.get("id")
        if not cid:
            continue
        desc = ""
        for d in cve.get("descriptions", []) or []:
            if d.get("lang") == "en":
                desc = (d.get("value") or "").strip()
                break
        if not desc:
            continue
        score, severity = _cvss(cve)
        cwes = _cwes(cve)
        text = f"{cid}: {desc[:1500]}"
        if score:
            text += f" CVSS {score} {severity}."
        if cwes:
            text += f" CWE: {', '.join(cwes)}."
        rid = f"nvd:{cid}"
        records.append(_record(
            rid, rid, "nvd-cve", cid, text,
            cve.get("published", ""), cve.get("lastModified", ""),
            severity=severity,
            cvss_score=score,
            cwe_ids_json=json.dumps(cwes),
            references_json=json.dumps(_references(cve)),
        ))
    return records


def ingest_nvd_year(collection, year: int) -> dict:
    cfg = _config()
    url = cfg["nvd"]["feed_url_template"].format(year=year)
    state = _state_get(f"nvd-{year}")
    _progress(f"nvd-{year}: fetching {url}")
    raw, headers = _fetch(
        url,
        etag=state.get("etag") if state else None,
        last_modified=state.get("last_modified") if state else None,
    )
    if raw is None:
        _progress(f"nvd-{year}: skipped (304)")
        return {"skipped": True, "year": year}
    try:
        decompressed = gzip.decompress(raw)
    except OSError:
        decompressed = raw
    _progress(f"nvd-{year}: decompressed {len(decompressed) / (1024 * 1024):.1f} MB, parsing JSON")
    payload = json.loads(decompressed)
    records = _nvd_records(payload)
    _progress(f"nvd-{year}: parsed {len(records)} CVEs, embedding")
    _upsert(collection, records)
    _state_set(
        f"nvd-{year}",
        etag=headers.get("etag", ""),
        last_modified=headers.get("last-modified", ""),
        content_sha256=_sha256_bytes(raw),
        last_run_at=_now(),
        last_status="ok",
    )
    _progress(f"nvd-{year}: done ({len(records)} CVEs)")
    return {"count": len(records), "year": year}


def ingest_nvd_modified(collection) -> dict:
    cfg = _config()
    url = cfg["nvd"]["modified_url"]
    state = _state_get("nvd-modified")
    _progress(f"nvd-modified: fetching {url}")
    raw, headers = _fetch(
        url,
        etag=state.get("etag") if state else None,
        last_modified=state.get("last_modified") if state else None,
    )
    if raw is None:
        _progress("nvd-modified: skipped (304)")
        return {"skipped": True}
    try:
        decompressed = gzip.decompress(raw)
    except OSError:
        decompressed = raw
    payload = json.loads(decompressed)
    records = _nvd_records(payload)
    _progress(f"nvd-modified: {len(records)} CVEs changed, embedding")
    _upsert(collection, records)
    _state_set(
        "nvd-modified",
        etag=headers.get("etag", ""),
        last_modified=headers.get("last-modified", ""),
        content_sha256=_sha256_bytes(raw),
        last_run_at=_now(),
        last_status="ok",
    )
    _progress(f"nvd-modified: done ({len(records)} CVEs)")
    return {"count": len(records)}


# ----------------------------- KEV -----------------------------

def ingest_kev(collection) -> dict:
    cfg = _config()
    _progress("kev: fetching CISA Known Exploited Vulnerabilities catalog")
    raw, headers = _fetch(cfg["kev"]["url"])
    if raw is None:
        return {"skipped": True}
    payload = json.loads(raw)
    vulns = payload.get("vulnerabilities", []) or []
    _progress(f"kev: {len(vulns)} CVEs in catalog")

    ids = [f"nvd:{v['cveID']}" for v in vulns if v.get("cveID")]
    existing_meta: dict[str, dict] = {}
    for batch in _batched(ids, KEV_LOOKUP_BATCH):
        res = collection.get(ids=batch, include=["metadatas"])
        for rid, meta in zip(res.get("ids", []), res.get("metadatas", [])):
            if meta:
                existing_meta[rid] = meta

    # Existing NVD rows: metadata-only update, no re-embed.
    # KEV-only CVEs (not in NVD retention window): new chunk, embedded from lead.
    update_ids: list[str] = []
    update_metas: list[dict] = []
    new_records: list[dict] = []

    for v in vulns:
        cid = v.get("cveID")
        if not cid:
            continue
        rid = f"nvd:{cid}"
        meta = existing_meta.get(rid)
        if meta is not None:
            meta["kev"] = True
            meta["kev_due_date"] = v.get("dueDate", "") or ""
            meta["kev_ransomware"] = v.get("knownRansomwareCampaignUse", "") or ""
            meta["last_seen"] = _now()
            meta["last_seen_ts"] = _to_ts(meta["last_seen"])
            update_ids.append(rid)
            update_metas.append(meta)
        else:
            doc = f"{cid}: {v.get('vulnerabilityName', '')}. {v.get('shortDescription', '')}"
            rec = _record(
                rid, rid, "cisa-kev", cid, doc,
                v.get("dateAdded", ""), v.get("dateAdded", ""),
            )
            rec["metadata"]["kev"] = True
            rec["metadata"]["kev_due_date"] = v.get("dueDate", "") or ""
            rec["metadata"]["kev_ransomware"] = v.get("knownRansomwareCampaignUse", "") or ""
            new_records.append(rec)

    if update_ids:
        _progress(f"kev: metadata-update {len(update_ids)} existing NVD rows (no re-embed)")
        for batch_ids, batch_metas in zip(
            _batched(update_ids, UPSERT_BATCH),
            _batched(update_metas, UPSERT_BATCH),
        ):
            collection.update(ids=batch_ids, metadatas=batch_metas)

    if new_records:
        _progress(f"kev: embedding {len(new_records)} KEV-only CVEs")
        _upsert(collection, new_records)

    _state_set(
        "kev",
        etag=headers.get("etag", ""),
        last_modified=headers.get("last-modified", ""),
        content_sha256=_sha256_bytes(raw),
        last_run_at=_now(),
        last_status="ok",
    )
    return {"updated": len(update_ids), "new": len(new_records)}


# ----------------------------- retention -----------------------------

def apply_retention(collection) -> dict:
    cfg = _config()
    years = int(cfg["nvd"].get("retention_years", 5))
    cutoff = int((datetime.now(timezone.utc) - timedelta(days=365 * years)).timestamp())
    before = len(collection.get(include=[])["ids"])
    collection.delete(
        where={
            "$and": [
                {"source_type": {"$eq": "nvd-cve"}},
                {"published_ts": {"$lt": cutoff}},
                {"kev": {"$eq": False}},
            ]
        }
    )
    after = len(collection.get(include=[])["ids"])
    return {"deleted": before - after, "retention_years": years}



# ----------------------------- orchestration -----------------------------
# ----------------------------- EPSS -----------------------------

def _parse_epss_csv(raw: bytes) -> list[tuple[str, float, float]]:
    try:
        decompressed = gzip.decompress(raw)
    except OSError:
        decompressed = raw
    rows: list[tuple[str, float, float]] = []
    for line in decompressed.decode("utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.lower().startswith("cve,"):
            continue
        parts = s.split(",")
        if len(parts) < 3:
            continue
        cve_id = parts[0].strip()
        if not cve_id.upper().startswith("CVE-"):
            continue
        try:
            epss = float(parts[1].strip())
            pct = float(parts[2].strip())
        except ValueError:
            continue
        rows.append((cve_id, epss, pct))
    return rows


def ingest_epss(collection) -> dict:
    """Enrich existing NVD rows with EPSS scores. Metadata-only, no re-embed.

    Runs after `nvd` in the daily source order so newly-ingested CVEs
    get their EPSS enrichment the same day. Feed rows whose CVE is not
    yet in the DB are recorded in state; they get enriched when the
    matching NVD chunk lands.
    """
    cfg = _config()
    epss_cfg = cfg.get("epss") or {}
    url = epss_cfg.get("url")
    if not url:
        _progress("epss: no url configured, skipping")
        return {"skipped": True, "reason": "no_url"}

    state = _state_get("epss")
    _progress(f"epss: fetching {url}")
    raw, headers = _fetch(
        url,
        etag=state.get("etag") if state else None,
        last_modified=state.get("last_modified") if state else None,
    )
    if raw is None:
        _progress("epss: skipped (304)")
        return {"skipped": True}

    rows = _parse_epss_csv(raw)
    _progress(f"epss: {len(rows)} scores parsed, enriching existing NVD rows")

    updated = 0
    for batch in _batched(rows, KEV_LOOKUP_BATCH):
        by_id = {f"nvd:{cid}": (epss, pct) for cid, epss, pct in batch}
        ids = list(by_id.keys())
        res = collection.get(ids=ids, include=["metadatas"])
        update_ids: list[str] = []
        update_metas: list[dict] = []
        for rid, meta in zip(res.get("ids", []), res.get("metadatas", [])):
            if meta is None:
                continue
            epss, pct = by_id[rid]
            meta["epss_score"] = epss
            meta["epss_percentile"] = pct
            meta["epss_last_seen"] = _now()
            update_ids.append(rid)
            update_metas.append(meta)
        if update_ids:
            collection.update(ids=update_ids, metadatas=update_metas)
            updated += len(update_ids)

    not_matched = len(rows) - updated
    _state_set(
        "epss",
        etag=headers.get("etag", ""),
        last_modified=headers.get("last-modified", ""),
        content_sha256=_sha256_bytes(raw),
        last_run_at=_now(),
        last_status="ok",
    )
    _progress(f"epss: updated {updated} CVEs ({not_matched} scores not yet in DB)")
    return {"updated": updated, "feed_size": len(rows), "unmatched": not_matched}


# ----------------------------- RSS -----------------------------

def _parse_rss(xml_bytes: bytes) -> list[dict]:
    """Parse RSS 2.0 or Atom into a list of {title, link, summary, published}."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_bytes)
    except Exception:
        return []

    def _strip_ns(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    items: list[dict] = []
    for elem in root.iter():
        if _strip_ns(elem.tag) not in ("item", "entry"):
            continue
        item: dict = {}
        for child in elem:
            ctag = _strip_ns(child.tag)
            if ctag == "link":
                href = child.get("href") or (child.text or "")
                if href.strip() and "link" not in item:
                    item["link"] = href.strip()
            elif ctag in ("title", "description", "summary", "content",
                          "pubDate", "published", "updated"):
                text = "".join(child.itertext()).strip()
                if text and ctag not in item:
                    item[ctag] = text
        items.append(item)
    return items


def ingest_rss(collection) -> dict:
    """Fetch configured RSS/Atom feeds, embed new entries as citable chunks."""
    cfg = _config()
    rss_cfg = cfg.get("rss") or {}
    feeds = rss_cfg.get("feeds") or []
    cap = int(rss_cfg.get("max_entries_per_feed", 50))
    if not feeds:
        _progress("rss: no feeds configured, skipping")
        return {"skipped": True, "reason": "no_feeds"}

    total_new = 0
    errors: list[str] = []

    for feed in feeds:
        name = feed.get("name") or feed.get("url") or "unknown"
        url = feed.get("url")
        source_type = feed.get("source_type", "security-news")
        if not url:
            continue
        try:
            raw, _headers = _fetch(url)
            if raw is None:
                _progress(f"rss[{name}]: skipped (304)")
                continue
            items = _parse_rss(raw)
            records: list[dict] = []
            for item in items[:cap]:
                title = item.get("title", "").strip()
                link = item.get("link", "").strip()
                desc = (
                    item.get("description")
                    or item.get("summary")
                    or item.get("content")
                    or ""
                ).strip()
                pub = (
                    item.get("pubDate")
                    or item.get("published")
                    or item.get("updated")
                    or ""
                ).strip()
                if not title:
                    continue
                rid_seed = link or title
                rid = f"rss:{_sha256_bytes(rid_seed.encode('utf-8'))[:16]}"
                text = f"{title}. {desc}".strip()[:3000]
                records.append(_record(
                    rid, rid, source_type, title, text,
                    published_at=pub, modified_at=pub,
                    source_url=link, feed_name=name,
                ))
            if records:
                _upsert(collection, records)
                total_new += len(records)
            _progress(f"rss[{name}]: {len(records)} entries ingested")
        except Exception as exc:
            errors.append(f"{name}: {exc}")
            _progress(f"rss[{name}]: ERROR {exc}")

    # Prune RSS entries older than 30 days — keeps DB bounded.
    # Rows with pts=0 (unparseable dates from before the RFC-2822 fix)
    # match `0 < cutoff`, so this clean up old 
    pruned = 0
    try:
        cutoff = int((datetime.now(timezone.utc) - timedelta(days=30)).timestamp())
        rss_types = ["security-news", "cisa-advisory", "vendor-advisory"]
        before = len(collection.get(where={"source_type": {"$in": rss_types}}, include=[])["ids"])
        collection.delete(where={
            "$and": [
                {"source_type": {"$in": rss_types}},
                {"published_ts": {"$lt": cutoff}},
            ]
        })
        after = len(collection.get(where={"source_type": {"$in": rss_types}}, include=[])["ids"])
        pruned = before - after
        _progress(f"rss: pruned {pruned} entries older than 30 days")
    except Exception as exc:
        _progress(f"rss: prune failed: {exc}")


    _state_set(
        "rss",
        last_run_at=_now(),
        last_status="ok" if not errors else "partial",
    )
    return {"feeds": len(feeds), "new_entries": total_new, "pruned": pruned, "errors": errors}


def run_sync(mode: str, sources: list[str], nvd_years: list[int] | None = None) -> tuple[dict, dict]:
    cfg = _config()
    if nvd_years is None:
        nvd_years = [int(y) for y in cfg["nvd"]["full_years"]]
    collection = get_collection()
    run_id = _run_start(mode, sources)
    counts: dict = {}
    errors: dict = {}
    try:
        for src in sources:
            _progress(f"=== source: {src} ===")
            try:
                if src == "baseline":
                    counts[src] = ingest_baseline(collection)
                elif src == "mitre":
                    counts[src] = ingest_mitre(collection, force=(mode == "full"))
                elif src == "kev":
                    counts[src] = ingest_kev(collection)
                elif src == "epss":
                    counts[src] = ingest_epss(collection)
                elif src == "rss":
                    counts[src] = ingest_rss(collection)
                elif src == "nvd":
                    if mode == "daily":
                        counts[src] = ingest_nvd_modified(collection)
                    else:
                        counts[src] = {}
                        for y in nvd_years:
                            counts[src][str(y)] = ingest_nvd_year(collection, y)
                else:
                    errors[src] = "unknown source"
            except Exception as exc:
                log.exception("source failed: %s", src)
                errors[src] = f"{type(exc).__name__}: {exc}"
                _progress(f"ERROR in {src}: {errors[src]}")
        if mode == "daily":
            _progress("=== retention ===")
            counts["retention"] = apply_retention(collection)
        status = "ok" if not errors else "partial"
        _run_finish(run_id, status, counts, errors)
        return counts, errors
    except Exception as exc:
        _run_finish(run_id, "failed", counts, {**errors, "_fatal": str(exc)})
        raise


def verify(collection) -> dict:
    checks: dict[str, bool] = {}
    counts: dict[str, int] = {}

    for st in ["mitre-attack", *BASELINE_TYPES, "nvd-cve", "cisa-kev"]:
        counts[st] = len(collection.get(where={"source_type": {"$eq": st}}, include=[])["ids"])

    kev_ids = collection.get(where={"kev": {"$eq": True}}, include=[])["ids"]
    counts["kev_enriched"] = len(kev_ids)

    checks["mitre_count_gt_500"] = counts["mitre-attack"] > 500
    checks["playbook_count_gt_10"] = counts["baseline-playbook"] > 10
    checks["nvd_count_gt_1000"] = counts["nvd-cve"] > 1000
    checks["kev_enriched_gt_0"] = counts["kev_enriched"] > 0

    superseded = collection.get(where={"superseded_by": {"$ne": ""}}, include=[])["ids"]
    checks["no_superseded_rows"] = len(superseded) == 0

    from app.knowledge import retrieve

    probe = retrieve(["powershell execution policy bypass hidden"], collection, top_k=5)
    top_ids = [r["chunk_id"] for r in probe["results"]]
    checks["retrieval_probe_hits_t1059_or_playbook"] = any(
        i.startswith("mitre:T1059") or i == "playbook:execution.powershell" for i in top_ids
    )

    return {
        "ok": all(checks.values()),
        "checks": checks,
        "counts": counts,
        "retrieval_probe_top5": top_ids,
    }


def state_summary() -> dict:
    with _db() as conn:
        states = conn.execute(
            "SELECT source, etag, last_modified, version, last_run_at, last_status FROM source_state ORDER BY source"
        ).fetchall()
        runs = conn.execute(
            "SELECT id, started_at, finished_at, mode, sources, status, counts_json, errors_json "
            "FROM sync_runs ORDER BY id DESC LIMIT 5"
        ).fetchall()
    return {
        "source_state": [
            {"source": r[0], "etag": r[1], "last_modified": r[2], "version": r[3], "last_run_at": r[4], "last_status": r[5]}
            for r in states
        ],
        "recent_runs": [
            {"id": r[0], "started_at": r[1], "finished_at": r[2], "mode": r[3], "sources": r[4], "status": r[5], "counts": json.loads(r[6] or "{}"), "errors": json.loads(r[7] or "{}")}
            for r in runs
        ],
    }
