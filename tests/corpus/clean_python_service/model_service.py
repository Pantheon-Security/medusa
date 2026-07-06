"""Recommendation scoring "agent" — a plain scikit-learn wrapper, not an LLM agent.

Named RecommendationAgent because that's the product's internal vocabulary,
not because it does anything security-relevant. Included in the FP corpus
specifically to exercise MEDUSA's harvested "agent"/"model" keyword rules
against a benign hit.
"""
import logging
from pathlib import Path

import joblib

logger = logging.getLogger(__name__)


class RecommendationAgent:
    """Loads a pre-trained, locally-built model and scores catalog items."""

    def __init__(self, model_path: str):
        self.model_path = Path(model_path)
        self._model = None

    def _ensure_loaded(self):
        if self._model is None:
            if not self.model_path.exists():
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
            # Model file is produced by our own training pipeline and shipped
            # alongside the service — not fetched from a remote/untrusted source.
            self._model = joblib.load(self.model_path)
        return self._model

    def score(self, query: str) -> dict:
        """Return a mapping of SKU -> relevance score for the given query."""
        model = self._ensure_loaded()
        features = self._vectorize(query)
        raw_scores = model.predict_proba([features])[0]
        return {sku: float(score) for sku, score in zip(model.classes_, raw_scores)}

    @staticmethod
    def _vectorize(query: str) -> list:
        """Very small bag-of-words style feature vector for demonstration."""
        tokens = query.lower().split()
        return [len(tokens), sum(len(t) for t in tokens)]
