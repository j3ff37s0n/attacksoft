"""Knowledge base retrieval: SQLite + NumPy embeddings + hybrid scoring."""

from __future__ import annotations

import re
import json
import sqlite3
from pathlib import Path
from typing import Any

import numpy as np
import httpx

DB_PATH = Path("/opt/pipeline/data/knowledge_v2.db")
OLLAMA_EMBED_URL = "http://127.0.0.1:11434/api/embed"
EMBED_MODEL = "nomic-embed-text"
EMBED_BATCH = 32

TOKEN_RE = re.compile(r"[a-zA-Z0-9_.\-]{2,}")


class OllamaEmbeddingFunction:
    def __init__(self, model: str = EMBED_MODEL, url: str = OLLAMA_EMBED_URL):
        self.model = model
        self.url = url

    def __call__(self, input):
        if isinstance(input, str):
            input = [input]
        out: list[list[float]] = []
        for i in range(0, len(input), EMBED_BATCH):
            batch = input[i : i + EMBED_BATCH]
            r = httpx.post(
                self.url,
                json={"model": self.model, "input": batch},
                timeout=300.0,
            )
            r.raise_for_status()
            out.extend(r.json()["embeddings"])
        return np.array(out, dtype=np.float32)


class SQLiteCollection:
    """A lightweight, ChromaDB-compatible interface for ingestion and retrieval."""

    def __init__(self, db_path: Path):
        self.conn = sqlite3.connect(str(db_path), timeout=10.0)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS chunks (
                id TEXT PRIMARY KEY,
                document TEXT,
                metadata TEXT,
                embedding BLOB
            )
        """)
        self.conn.commit()

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]

    def upsert(self, ids: list[str], documents: list[str], metadatas: list[dict], embeddings: list[Any]) -> None:
        rows = []
        for i in range(len(ids)):
            emb = embeddings[i]
            if hasattr(emb, "tobytes"):
                emb_bytes = emb.tobytes()
            else:
                emb_bytes = np.array(emb, dtype=np.float32).tobytes()
            rows.append((ids[i], documents[i], json.dumps(metadatas[i]), emb_bytes))
        
        self.conn.executemany(
            "INSERT OR REPLACE INTO chunks (id, text, metadata, embedding) VALUES (?, ?, ?, ?)",
            rows
        )
        self.conn.commit()

    def update(self, ids: list[str], metadatas: list[dict]) -> None:
        rows = [(json.dumps(metadatas[i]), ids[i]) for i in range(len(ids))]
        self.conn.executemany("UPDATE chunks SET metadata = ? WHERE id = ?", rows)
        self.conn.commit()

    def get(self, where: dict | None = None, include: list[str] | None = None, ids: list[str] | None = None) -> dict:
        if ids is not None and where is None:
            # fetch only the requested IDs via SQL IN clause.
            placeholders = ",".join("?" * len(ids))
            cursor = self.conn.execute(
                f"SELECT id, document, metadata FROM chunks WHERE id IN ({placeholders})",
                ids,
            )
            rows = cursor.fetchall()
            res_ids, res_docs, res_metas = [], [], []
            for row in rows:
                res_ids.append(row[0])
                if include is None or "documents" in include:
                    res_docs.append(row[1])
                if include is None or "metadatas" in include:
                    res_metas.append(json.loads(row[2]))
            result = {"ids": res_ids}
            if include is None or "documents" in include:
                result["documents"] = res_docs
            if include is None or "metadatas" in include:
                result["metadatas"] = res_metas
            return result

        cursor = self.conn.execute("SELECT id, text, metadata FROM chunks")
        all_rows = cursor.fetchall()

        res_ids = []
        res_docs = []
        res_metas = []

        for row in all_rows:
            cid = row[0]
            doc = row[1]
            meta = json.loads(row[2])
            
            if ids is not None and cid not in ids:
                continue
                
            if where is not None and not self._match_where(meta, where):
                continue
                
            res_ids.append(cid)
            if include is None or "documents" in include:
                res_docs.append(doc)
            if include is None or "metadatas" in include:
                res_metas.append(meta)
                
        result = {"ids": res_ids}
        if include is None or "documents" in include:
            result["documents"] = res_docs
        if include is None or "metadatas" in include:
            result["metadatas"] = res_metas
        return result

    def delete(self, ids: list[str] | None = None, where: dict | None = None) -> None:
        if ids:
            placeholders = ",".join("?" for _ in ids)
            self.conn.execute(f"DELETE FROM chunks WHERE id IN ({placeholders})", ids)
            self.conn.commit()
        elif where:
            cursor = self.conn.execute("SELECT id, metadata FROM chunks")
            to_delete = []
            for row in cursor.fetchall():
                cid = row[0]
                meta = json.loads(row[1])
                if self._match_where(meta, where):
                    to_delete.append(cid)
            if to_delete:
                placeholders = ",".join("?" for _ in to_delete)
                self.conn.execute(f"DELETE FROM chunks WHERE id IN ({placeholders})", to_delete)
                self.conn.commit()

    def _match_where(self, meta: dict, where: dict) -> bool:
        for k, v in where.items():
            if k == "$and":
                for sub_where in v:
                    if not self._match_where(meta, sub_where):
                        return False
                return True
            if isinstance(v, dict):
                if "$eq" in v and meta.get(k) != v["$eq"]: return False
                if "$ne" in v and meta.get(k) == v["$ne"]: return False
                if "$in" in v and meta.get(k) not in v["$in"]: return False
                if "$lt" in v:
                    if meta.get(k) is None: return False
                    try:
                        if not (meta.get(k) < v["$lt"]): return False
                    except TypeError:
                        return False
            else:
                if meta.get(k) != v: return False
        return True


def get_collection() -> SQLiteCollection:
    return SQLiteCollection(DB_PATH)


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in TOKEN_RE.findall(text)]


def _keyword_overlap(query_tokens: list[str], doc_tokens: list[str]) -> float:
    if not query_tokens:
        return 0.0
    doc_set = set(doc_tokens)
    hits = sum(1 for t in query_tokens if t in doc_set)
    return hits / len(query_tokens)


def derive_queries(bundle: dict, max_queries: int = 20) -> list[str]:
    """Derive retrieval queries from the sanitized evidence bundle.

    Two phases:
      1. BEHAVIORAL — command lines, processes, network, DNS, registry.
         Matches baseline-playbook and mitre-attack chunks by behavior.
      2. STATIC — versioninfo (→ CVE), peid_signature (→ family playbook),
         report_ttp (→ ATT&CK), capability-revealing PE imports (→ playbook),
         imphash (→ family lookup, if your DB has it).

    Static queries run AFTER behavioral so behavioral relevance takes
    priority in top_k selection. For a no-op sample with rich static
    properties, static queries fill the space that behavioral queries
    would otherwise leave empty.
    """
    priority_cats = [
        "command_line", "process", "network", "dns",
        "credential_access", "persistence", "file", "registry",
    ]
    queries: list[str] = []
    seen: set[str] = set()

    def _add(q: str) -> None:
        q = q.strip()
        if q and q not in seen:
            seen.add(q)
            queries.append(q)

    # --- Phase 1: behavioral queries (cap 10) ---
    behavioral_added = 0
    for cat in priority_cats:
        for fact in bundle.get("facts", []):
            if fact.get("category") != cat:
                continue
            verbatim = fact.get("verbatim", "")
            if not verbatim or verbatim in seen:
                continue
            if any(x in verbatim.lower() for x in
                   ('.local', '.arpa', '224.0.0.', '239.255.')):
                continue
            _add(f"{cat}: {verbatim}")
            behavioral_added += 1
            if behavioral_added >= 10:
                break
        if behavioral_added >= 10:
            break

    # --- Phase 2: static feature queries ---
    versioninfo: dict[str, str] = {}
    pe_imports: list[str] = []
    peid_sigs: list[str] = []
    report_ttps: list[str] = []
    imphash = ""

    for fact in bundle.get("facts", []):
        key = fact.get("key", "")
        val = fact.get("verbatim") or fact.get("value")
        if not val:
            continue
        val_s = str(val)
        if key.startswith("versioninfo_"):
            versioninfo[key[len("versioninfo_"):]] = val_s
        elif key == "pe_import":
            pe_imports.append(val_s)
        elif key == "peid_signature":
            peid_sigs.append(val_s)
        elif key == "report_ttp":
            report_ttps.append(val_s)
        elif key == "pe_imphash":
            imphash = val_s

    # 2a. Product + version → CVE lookup
    product = versioninfo.get("ProductName", "").strip()
    version = versioninfo.get("ProductVersion", "").strip()
    file_desc = versioninfo.get("FileDescription", "").strip()
    if product and version:
        _add(f"CVE {product} {version}")
        _add(f"{product} {version} vulnerability")
    elif file_desc:
        _add(f"CVE {file_desc}")

    # 2b. OriginalFilename mismatch hint (spoofing signal)
    orig = versioninfo.get("OriginalFilename", "").strip()
    if orig and file_desc and orig.lower() not in file_desc.lower():
        _add(f"spoofing {file_desc} {orig}")

    # 2c. PEiD signature → family playbook
    for sig in peid_sigs[:3]:
        _add(f"{sig} malware family")
        _add(f"{sig} playbook")

    # 2d. Cuckoo's own ATT&CK mapping → mitigation retrieval
    for ttp in report_ttps[:5]:
        _add(f"MITRE {ttp}")
        _add(f"{ttp} mitigation")

    # 2e. Capability-revealing PE imports → playbook hint
    capability_imports = {
        "cryptencrypt":       "ransomware encryption",
        "cryptgenkey":        "ransomware encryption",
        "bcryptencrypt":      "ransomware encryption",
        "createremotethread": "process injection",
        "virtualallocex":     "process injection",
        "writeprocessmemory": "process injection",
        "setwindowshookex":   "persistence hook",
        "regsetvalueex":      "persistence registry",
        "urldownloadtofile":  "downloader",
        "winhttpopen":        "downloader c2",
        "winhttpsendrequest": "downloader c2",
        "adjusttokenprivileges": "privilege escalation",
        "isdebuggerpresent":  "anti-debug evasion",
        "checkremotedebuggerpresent": "anti-debug evasion",
    }
    seen_cap: set[str] = set()
    for imp in pe_imports:
        imp_l = imp.lower()
        for needle, cap in capability_imports.items():
            if needle in imp_l and cap not in seen_cap:
                _add(f"{cap} playbook mitigation")
                seen_cap.add(cap)

    # 2f. Imphash
    if imphash:
        _add(f"imphash {imphash}")

    return queries[:max_queries]


def retrieve(queries: list[str], collection: SQLiteCollection, top_k: int = 12, threshold: float = 0.30) -> dict:
    if not queries:
        return {
            "results": [],
            "confidence": {
                "threshold": threshold, "max_score": 0.0,
                "mean_top_k_score": 0.0, "sufficient": False,
                "reason": "no queries", "selected_chunk_ids": []
            }
        }

    # Compute query embeddings FIRST so we know the expected dimension
    embed_fn = OllamaEmbeddingFunction()
    q_vectors = embed_fn(queries)
    expected_dim = q_vectors.shape[1]

    cursor = collection.conn.execute("SELECT id, text, metadata, embedding FROM chunks")
    rows = cursor.fetchall()

    if not rows:
        return {
            "results": [],
            "confidence": {
                "threshold": threshold, "max_score": 0.0,
                "mean_top_k_score": 0.0, "sufficient": False,
                "reason": "database empty", "selected_chunk_ids": []
            }
        }

    ids: list[str] = []
    texts: list[str] = []
    metas: list[dict] = []
    vectors: list[np.ndarray] = []

    for r in rows:
        vec = np.frombuffer(r[3], dtype=np.float32)
        # Defensive: skip any vector whose dimension doesn't match nomic-embed-text
        if len(vec) != expected_dim:
            continue
        ids.append(r[0])
        texts.append(r[1])
        metas.append(json.loads(r[2]))
        vectors.append(vec)

    if not vectors:
        return {
            "results": [],
            "confidence": {
                "threshold": threshold, "max_score": 0.0,
                "mean_top_k_score": 0.0, "sufficient": False,
                "reason": f"no vectors matched expected dimension {expected_dim}",
                "selected_chunk_ids": []
            }
        }

    matrix = np.vstack(vectors)
    scores = np.dot(q_vectors, matrix.T)

    hits = {}
    query_tokens = [_tokenize(q) for q in queries]

    for i, q in enumerate(queries):
        top_indices = np.argsort(scores[i])[-40:][::-1]

        for idx in top_indices:
            chunk_id = ids[idx]
            semantic = float(scores[i][idx])
            semantic = max(0.0, min(1.0, semantic))

            doc_text = texts[idx]
            kw = _keyword_overlap(query_tokens[i], _tokenize(doc_text))
            fused = 0.7 * semantic + 0.3 * kw

            meta = metas[idx]
            prev = hits.get(chunk_id)
            if prev is None or fused > prev["score_fused"]:
                hits[chunk_id] = {
                    "chunk_id": chunk_id,
                    "source_id": meta.get("source_id", chunk_id),
                    "source_type": meta.get("source_type", "unknown"),
                    "title": meta.get("title", ""),
                    "text": doc_text,
                    "score_semantic": round(semantic, 4),
                    "score_keyword": round(kw, 4),
                    "score_fused": round(fused, 4),
                }

    ranked = sorted(hits.values(), key=lambda x: -x["score_fused"])[:top_k]
    max_score = ranked[0]["score_fused"] if ranked else 0.0
    top5 = ranked[:5]
    mean_top = sum(r["score_fused"] for r in top5) / len(top5) if top5 else 0.0
    sufficient = max_score >= threshold

    return {
        "results": ranked,
        "confidence": {
            "threshold": threshold,
            "max_score": round(max_score, 4),
            "mean_top_k_score": round(mean_top, 4),
            "sufficient": sufficient,
            "reason": f"max={max_score:.3f} threshold={threshold}",
            "selected_chunk_ids": [r["chunk_id"] for r in ranked],
        },
    }
