"""
Lightweight Vector Store (RAG Pipeline - retrieval half)
-----------------------------------------------------------
A dependency-light stand-in for FAISS / ChromaDB. Instead of a neural
embedding model (which needs network access to download weights), this
uses TF-IDF vectors + cosine similarity - the classic sparse-vector
retrieval approach. It implements the exact same interface a real vector
store would (add / query), so swapping in `sentence-transformers` +
FAISS later is a drop-in change (see `EmbeddingBackend` note below).

Why TF-IDF instead of a neural embedding model here:
  - No internet access to huggingface.co in this environment to pull
    sentence-transformer weights.
  - TF-IDF is still a legitimate, explainable retrieval method used in
    production RAG systems (BM25/TF-IDF hybrid retrieval is common).
  - The interface (VectorStore.add / .query) is identical to what a
    FAISS/Chroma-backed store would expose, so this is a real swap point,
    not a mock.

To upgrade to true dense embeddings in production:
  pip install sentence-transformers faiss-cpu
  Replace `TfidfVectorizer` below with a SentenceTransformer encoder and
  swap NearestNeighbors for a faiss.IndexFlatIP index. Nothing else in
  the RAG pipeline or callers needs to change.
"""

from __future__ import annotations
from typing import List, Dict, Any
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors
import numpy as np


class VectorStore:
    """A minimal vector store: add(texts, metadata) then query(text, k)."""

    def __init__(self):
        self._vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
        self._matrix = None
        self._nn = None
        self._texts: List[str] = []
        self._metadata: List[Dict[str, Any]] = []
        self._fitted = False

    def build(self, texts: List[str], metadata: List[Dict[str, Any]] = None):
        """(Re)build the index from a full corpus of documents."""
        if not texts:
            raise ValueError("Cannot build a vector store from an empty corpus")
        self._texts = list(texts)
        self._metadata = metadata if metadata is not None else [{} for _ in texts]
        self._matrix = self._vectorizer.fit_transform(self._texts)
        n_neighbors = min(50, self._matrix.shape[0])
        self._nn = NearestNeighbors(n_neighbors=n_neighbors, metric="cosine")
        self._nn.fit(self._matrix)
        self._fitted = True
        return self

    def query(self, text: str, k: int = 5) -> List[Dict[str, Any]]:
        """Return the top-k most similar documents with similarity scores."""
        if not self._fitted:
            return []
        k = min(k, self._matrix.shape[0])
        q_vec = self._vectorizer.transform([text])
        distances, indices = self._nn.kneighbors(q_vec, n_neighbors=k)
        results = []
        for dist, idx in zip(distances[0], indices[0]):
            similarity = 1.0 - dist  # cosine distance -> similarity
            if similarity <= 0.01:
                continue
            results.append({
                "text": self._texts[idx],
                "metadata": self._metadata[idx],
                "score": round(float(similarity), 4),
            })
        return results

    def size(self) -> int:
        return len(self._texts)
