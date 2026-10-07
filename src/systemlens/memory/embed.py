"""Embedder protocol + a dependency-free default.

HashingEmbedder needs only numpy: it hashes character n-grams into a fixed-
width vector (the "hashing trick"), which is enough to cluster near-duplicate
log templates for FAISS similarity search. No model download, no torch, no
network call — appropriate for a few hundred distinct error templates on a
7GB local machine. Swap in a real sentence-transformers/remote-API embedder
later by implementing the same protocol; nothing else in the codebase
depends on the concrete class.
"""
from __future__ import annotations

import re
from typing import Protocol

import numpy as np

_TOKEN_RE = re.compile(r"[a-zA-Z]{2,}|<\w+>")


class Embedder(Protocol):
    dim: int

    def embed(self, text: str) -> np.ndarray: ...
    def embed_batch(self, texts: list[str]) -> np.ndarray: ...


class HashingEmbedder:
    def __init__(self, dim: int = 256, ngram: int = 3):
        self.dim = dim
        self._ngram = ngram

    def _ngrams(self, text: str) -> list[str]:
        tokens = _TOKEN_RE.findall(text.lower())
        joined = " ".join(tokens)
        n = self._ngram
        if len(joined) < n:
            return [joined] if joined else []
        return [joined[i:i + n] for i in range(len(joined) - n + 1)]

    def embed(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype=np.float32)
        for gram in self._ngrams(text):
            idx = hash(gram) % self.dim
            vec[idx] += 1.0
        norm = np.linalg.norm(vec)
        return vec / norm if norm > 0 else vec

    def embed_batch(self, texts: list[str]) -> np.ndarray:
        return np.stack([self.embed(t) for t in texts]) if texts else np.zeros((0, self.dim), dtype=np.float32)
