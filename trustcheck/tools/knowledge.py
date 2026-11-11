"""Tool: retrieve known scam patterns from a local knowledge base (RAG).

Documents live in data/kb/*.md (written from public FTC / FBI IC3 / university
career-office guidance). Uses sentence-transformers + ChromaDB when installed;
otherwise falls back to a TF-IDF retriever so the project runs with zero setup.
"""
from __future__ import annotations

import re
from functools import lru_cache

from .. import config


def _load_chunks() -> list[dict]:
    chunks = []
    for path in sorted(config.KB_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        # one chunk per "## " section
        sections = re.split(r"\n(?=## )", text)
        for sec in sections:
            sec = sec.strip()
            if len(sec) < 40:
                continue
            title = sec.splitlines()[0].lstrip("# ").strip()
            chunks.append({"source": path.name, "title": title, "text": sec})
    return chunks


class _TfidfRetriever:
    def __init__(self, chunks):
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.chunks = chunks
        self.vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
        self.m = self.vec.fit_transform([c["text"] for c in chunks])

    def search(self, query, k):
        from sklearn.metrics.pairwise import cosine_similarity
        sims = cosine_similarity(self.vec.transform([query]), self.m)[0]
        order = sims.argsort()[::-1][:k]
        return [(self.chunks[i], float(sims[i])) for i in order]


class _ChromaRetriever:
    def __init__(self, chunks):
        import chromadb
        from chromadb.utils import embedding_functions
        ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        client = chromadb.PersistentClient(path=str(config.DATA_DIR / "chroma"))
        self.col = client.get_or_create_collection("scam_kb", embedding_function=ef,
                                                   metadata={"hnsw:space": "cosine"})
        if self.col.count() != len(chunks):
            existing = self.col.get()["ids"]
            if existing:
                self.col.delete(ids=existing)
            self.col.add(ids=[str(i) for i in range(len(chunks))],
                         documents=[c["text"] for c in chunks],
                         metadatas=[{"source": c["source"], "title": c["title"]} for c in chunks])
        self.chunks = chunks

    def search(self, query, k):
        r = self.col.query(query_texts=[query], n_results=k)
        out = []
        for i, dist in zip(r["ids"][0], r["distances"][0]):
            out.append((self.chunks[int(i)], 1 - float(dist)))
        return out


@lru_cache(maxsize=1)
def get_retriever():
    chunks = _load_chunks()
    try:
        return _ChromaRetriever(chunks), "chroma+minilm"
    except Exception:
        return _TfidfRetriever(chunks), "tfidf"


def search_scam_knowledge(query: str, k: int = 3) -> dict:
    retriever, backend = get_retriever()
    hits = retriever.search(query, k)
    return {
        "tool": "search_scam_knowledge",
        "backend": backend,
        "matches": [
            {"title": c["title"], "source": c["source"], "score": round(s, 3), "text": c["text"][:700]}
            for c, s in hits if s > 0.05
        ],
        "findings": [],
        "risk_points": 0,
    }
