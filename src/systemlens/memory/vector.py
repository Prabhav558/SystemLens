"""Optional per-project FAISS similarity index over resolved error templates.

This is strictly an accelerator over ProjectStore.similar_resolved(): if
faiss-cpu isn't installed, or `memory.use_faiss` is off in config, callers
fall back to the SQLite category-match query and the tool works identically,
just with less semantic recall. Rebuilt from SQLite in-memory on every
startup — SQLite is always the source of truth, never this index, and at
the volume a handful of local projects produce (a few hundred templates,
ever) a rebuild is effectively instant. Deliberately not persisted to disk:
nothing short-circuits the unconditional startup rebuild to make a cached
copy worth the added complexity of keeping a FAISS file and its
index-position-to-fingerprint mapping in lockstep with SQLite.
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np

from systemlens.core.models import PriorIncident
from systemlens.memory.embed import Embedder
from systemlens.memory.store import ProjectStore

logger = logging.getLogger("systemlens.vector")

try:
    import faiss
    _FAISS_AVAILABLE = True
except ImportError:
    faiss = None  # type: ignore
    _FAISS_AVAILABLE = False


class VectorIndex:
    def __init__(self, embedder: Embedder):
        self.embedder = embedder
        self._index = None
        self._fingerprints: list[str] = []

    @staticmethod
    def available() -> bool:
        return _FAISS_AVAILABLE

    def rebuild(self, store: ProjectStore) -> None:
        if not _FAISS_AVAILABLE:
            return
        pairs = store.all_resolved_templates()
        self._fingerprints = [fp for fp, _ in pairs]
        if not pairs:
            self._index = faiss.IndexFlatIP(self.embedder.dim)
            return
        vectors = self.embedder.embed_batch([t for _, t in pairs])
        index = faiss.IndexFlatIP(self.embedder.dim)
        index.add(vectors)
        self._index = index

    def search(self, template: str, store: ProjectStore, top_k: int = 3) -> list[PriorIncident]:
        if not _FAISS_AVAILABLE or self._index is None or self._index.ntotal == 0:
            return []
        query = self.embedder.embed(template).reshape(1, -1)
        scores, idxs = self._index.search(query, min(top_k, self._index.ntotal))
        results: list[PriorIncident] = []
        for score, idx in zip(scores[0], idxs[0]):
            if idx < 0 or score < 0.35:  # cosine-ish threshold; skip weak matches
                continue
            prior = store.get_prior(self._fingerprints[idx])
            if prior:
                results.append(prior)
        return results
