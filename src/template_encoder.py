"""
Semantic Template Encoder.

Wraps a sentence-transformer to convert Drain log templates into a continuous
vector space. Provides:
  - Batch embedding of known templates at training time
  - Nearest-neighbor lookup for out-of-vocabulary templates at inference time
  - Persistence (save/load) of fitted encoder state

The encoder is read-only at inference: it does not learn from new logs. Unknown
templates are projected to the nearest known template by cosine similarity,
producing functional equivalence rather than catastrophic OOV failure.
"""

from __future__ import annotations

import hashlib
import pickle
import re
from pathlib import Path

import numpy as np


_PLACEHOLDER_NORMALIZED = '<VAR>'
_HASH_FALLBACK_DIM = 384
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z_0-9]+|<VAR>")


def _stable_hash(token: str) -> int:
    """Deterministic hash that survives process restarts."""
    return int.from_bytes(
        hashlib.blake2b(token.encode('utf-8'), digest_size=8).digest(),
        'little',
    )


def _hash_vectorize(text: str, dim: int = _HASH_FALLBACK_DIM) -> np.ndarray:
    """
    Feature-hashing encoder: word tokens + character trigrams projected into
    `dim` dimensions with signed accumulation, then L2-normalized.

    Produces a dense semantic-similarity vector with cosine geometry roughly
    matching the input lexical overlap. No external model required.
    """
    vec = np.zeros(dim, dtype=np.float32)
    lc = text.lower()

    for tok in _TOKEN_RE.findall(lc):
        h = _stable_hash('w:' + tok)
        idx = h % dim
        sign = 1.0 if (h >> 63) & 1 else -1.0
        vec[idx] += sign

    if len(lc) >= 3:
        for i in range(len(lc) - 2):
            tri = lc[i:i + 3]
            h = _stable_hash('3:' + tri)
            idx = h % dim
            sign = 1.0 if (h >> 63) & 1 else -1.0
            vec[idx] += sign * 0.3

    norm = float(np.linalg.norm(vec))
    if norm > 0.0:
        vec /= norm
    return vec


def _normalize_template(template: str) -> str:
    """Replace Drain's <*> wildcard with a single readable token for the encoder."""
    return template.replace('<*>', _PLACEHOLDER_NORMALIZED)


class TemplateEncoder:
    """Sentence-transformer-backed embedding of log templates with NN fallback."""

    def __init__(self, model_name: str = 'all-MiniLM-L6-v2',
                 oov_min_similarity: float = 0.55):
        self.model_name = model_name
        self.oov_min_similarity = oov_min_similarity
        self.embedding_dim: int = 0
        # event_id -> row index in self._matrix
        self._event_to_idx: dict[str, int] = {}
        self._idx_to_event: list[str] = []
        self._matrix: np.ndarray | None = None  # (n_templates, embedding_dim), L2-normalized
        self._oov_cache: dict[str, str] = {}    # template_text -> resolved event_id
        self._model = None

    def _ensure_model(self):
        if self._model is not None or self.model_name == 'hash':
            if self.model_name == 'hash':
                self.embedding_dim = _HASH_FALLBACK_DIM
                self._model = 'hash'
            return
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name)
            self.embedding_dim = self._model.get_sentence_embedding_dimension()
        except Exception as exc:  # network blocked, package missing, etc.
            print(f'  Warning: sentence-transformer "{self.model_name}" '
                  f'unavailable ({type(exc).__name__}); falling back to '
                  f'deterministic hash encoder ({_HASH_FALLBACK_DIM}-dim).')
            self.model_name = 'hash'
            self.embedding_dim = _HASH_FALLBACK_DIM
            self._model = 'hash'

    @staticmethod
    def _l2_normalize(mat: np.ndarray) -> np.ndarray:
        norms = np.linalg.norm(mat, axis=1, keepdims=True)
        norms[norms == 0.0] = 1.0
        return mat / norms

    def fit(self, event_to_template: dict[str, str]):
        """
        Embed every known (event_id, template) pair. Idempotent. Sorts by
        event_id so the row order is reproducible.
        """
        self._ensure_model()
        ordered = sorted(event_to_template.items(), key=lambda kv: kv[0])
        self._idx_to_event = [eid for eid, _ in ordered]
        self._event_to_idx = {eid: i for i, eid in enumerate(self._idx_to_event)}
        texts = [_normalize_template(tmpl) for _, tmpl in ordered]
        if not texts:
            self._matrix = np.zeros((0, self.embedding_dim), dtype=np.float32)
            return
        if self._model == 'hash':
            emb = np.stack([_hash_vectorize(t) for t in texts]).astype(np.float32)
        else:
            emb = self._model.encode(texts, batch_size=64,
                                     show_progress_bar=False,
                                     convert_to_numpy=True).astype(np.float32)
        self._matrix = self._l2_normalize(emb)

    def embedding_matrix(self) -> np.ndarray:
        """Return the (n_templates, embedding_dim) matrix in event_id-sorted order."""
        if self._matrix is None:
            raise RuntimeError('TemplateEncoder has not been fit().')
        return self._matrix.copy()

    def event_index(self, event_id: str) -> int | None:
        """Row index of a known event_id, or None if unknown."""
        return self._event_to_idx.get(event_id)

    def known_event_ids(self) -> list[str]:
        return list(self._idx_to_event)

    def encode_one(self, template: str) -> np.ndarray:
        """Encode a single template to a normalized embedding vector."""
        self._ensure_model()
        text = _normalize_template(template)
        if self._model == 'hash':
            return _hash_vectorize(text)
        emb = self._model.encode([text], show_progress_bar=False,
                                 convert_to_numpy=True).astype(np.float32)
        return self._l2_normalize(emb)[0]

    def encode_batch(self, templates: list[str]) -> np.ndarray:
        """Encode a list of templates -> (n, embedding_dim) normalized matrix."""
        if not templates:
            return np.zeros((self.embedding_dim or _HASH_FALLBACK_DIM,),
                            dtype=np.float32).reshape(0, -1)
        self._ensure_model()
        texts = [_normalize_template(t) for t in templates]
        if self._model == 'hash':
            emb = np.stack([_hash_vectorize(t) for t in texts]).astype(np.float32)
            return emb  # already normalized by _hash_vectorize
        emb = self._model.encode(texts, batch_size=64, show_progress_bar=False,
                                 convert_to_numpy=True).astype(np.float32)
        return self._l2_normalize(emb)

    def resolve(self, event_id: str, template: str) -> tuple[str, float]:
        """
        Map an event_id+template to a known event_id.

        - If event_id is already known, return (event_id, 1.0).
        - Otherwise embed the template and find the nearest known event_id by
          cosine similarity. Return (matched_event_id, similarity).
        - If no known template clears the similarity floor, return
          ('<unk>', best_similarity).
        """
        if event_id in self._event_to_idx:
            return event_id, 1.0
        cached = self._oov_cache.get(template)
        if cached is not None:
            return cached, 0.99
        if self._matrix is None or self._matrix.shape[0] == 0:
            return '<unk>', 0.0
        emb = self.encode_one(template)
        sims = self._matrix @ emb
        best_idx = int(np.argmax(sims))
        best_sim = float(sims[best_idx])
        if best_sim < self.oov_min_similarity:
            return '<unk>', best_sim
        resolved = self._idx_to_event[best_idx]
        self._oov_cache[template] = resolved
        return resolved, best_sim

    def save(self, path: Path):
        state = {
            'model_name': self.model_name,
            'oov_min_similarity': self.oov_min_similarity,
            'embedding_dim': self.embedding_dim,
            'event_to_idx': self._event_to_idx,
            'idx_to_event': self._idx_to_event,
            'matrix': self._matrix,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(state, f)

    @classmethod
    def load(cls, path: Path) -> 'TemplateEncoder':
        with open(path, 'rb') as f:
            state = pickle.load(f)
        enc = cls(model_name=state['model_name'],
                  oov_min_similarity=state['oov_min_similarity'])
        enc.embedding_dim = state['embedding_dim']
        enc._event_to_idx = state['event_to_idx']
        enc._idx_to_event = state['idx_to_event']
        enc._matrix = state['matrix']
        return enc
