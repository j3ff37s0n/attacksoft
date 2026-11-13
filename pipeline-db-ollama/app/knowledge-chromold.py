"""Knowledge base retrieval: sqllite + Ollama embeddings + hybrid scoring.
If you see chroma, it's just the alias for sqllite. Chroma changed due to version issues.
"""

from __future__ import annotations

import re
from pathlib import Path

import chromadb
import numpy as np
import httpx

CHROMA_PATH = Path("/opt/pipeline/data/chroma")
OLLAMA_EMBED_URL = "http://127.0.0.1:11434/api/embed"
EMBED_MODEL = "nomic-embed-text"
COLLECTION_NAME = "knowledge"
EMBED_DIM = 768
EMBED_BATCH = 32

TOKEN_RE = re.compile(r"[a-zA-Z0-9_.\-]{2,}")


class OllamaEmbeddingFunction:
    """Chroma 0.6.x embedding function backed by Ollama /api/embed."""

    def __init__(self, model: str = EMBED_MODEL, url: str = OLLAMA_EMBED_URL):
        self.model = model
        self.url = url

    def name(self) -> str:
        return "ollama-nomic-embed"

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


def get_collection():
    import os
    os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
    os.environ.setdefault("CHROMA_TELEMETRY_ENABLED", "False")
    
    # Connect to the isolated ChromaDB service on port 8001
    client = chromadb.HttpClient(host="127.0.0.1", port=8001)
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=OllamaEmbeddingFunction(),
        metadata={"hnsw:space": "cosine"},
    )


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in TOKEN_RE.findall(text)]


def _keyword_overlap(query_tokens: list[str], doc_tokens: list[str]) -> float:
    if not query_tokens:
        return 0.0
    doc_set = set(doc_tokens)
    hits = sum(1 for t in query_tokens if t in doc_set)
    return hits / len(query_tokens)


def derive_queries(bundle: dict, max_queries: int = 10) -> list[str]:
    priority = [
        "command_line",
        "process",
        "network",
        "dns",
        "credential_access",
        "persistence",
        "file",
        "registry",
    ]
    queries: list[str] = []
    seen: set[str] = set()
    for cat in priority:
        for fact in bundle.get("facts", []):
            if fact.get("category") != cat:
                continue
            verbatim = fact.get("verbatim", "")
            if not verbatim or verbatim in seen:
                continue
            seen.add(verbatim)
            queries.append(f"{cat}: {verbatim}")
            if len(queries) >= max_queries:
                return queries
    return queries


def retrieve(queries: list[str], collection, top_k: int = 12, threshold: float = 0.30) -> dict:
    if not queries:
        return {
            "results": [],
            "confidence": {
                "threshold": threshold,
                "max_score": 0.0,
                "mean_top_k_score": 0.0,
                "sufficient": False,
                "reason": "no queries",
                "selected_chunk_ids": [],
            },
        }

    query_tokens = [_tokenize(q) for q in queries]
    hits: dict[str, dict] = {}

    for i, q in enumerate(queries):
        # 0.6.3 uses query_texts natively with the embedding function
        r = collection.query(query_texts=[q], n_results=max(top_k * 2, 20))
        ids = r.get("ids", [[]])[0]
        docs = r.get("documents", [[]])[0]
        metas = r.get("metadatas", [[]])[0]
        dists = r.get("distances", [[]])[0]
        for j, chunk_id in enumerate(ids):
            distance = float(dists[j]) if j < len(dists) else 1.0
            semantic = max(0.0, 1.0 - distance)
            doc_text = docs[j] if j < len(docs) else ""
            kw = _keyword_overlap(query_tokens[i], _tokenize(doc_text))
            fused = 0.7 * semantic + 0.3 * kw
            meta = metas[j] if j < len(metas) else {}
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
