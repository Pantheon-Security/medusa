"""Small Flask-style API for a product catalog with an ML recommendation agent.

Self-authored fixture for MEDUSA's FP-regression golden-file test (PR-009).
Deliberately "boring but realistic" code: normal request/response handling,
config via environment variables, and business logic that happens to use
security-adjacent vocabulary (agent, prompt, model, token) in benign contexts
— this is what stress-tests the harvested keyword-mention rules without
containing any real vulnerability.
"""
import logging
import os

import requests
from flask import Flask, jsonify, request

from .model_service import RecommendationAgent
from .utils import sanitize_query, truncate_response

app = Flask(__name__)
logger = logging.getLogger(__name__)

API_BASE_URL = os.environ.get("CATALOG_API_URL", "https://catalog.internal.example.com")
API_TIMEOUT_SECONDS = 5

agent = RecommendationAgent(model_path=os.environ.get("MODEL_PATH", "models/recommender.pkl"))


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/recommend", methods=["POST"])
def recommend():
    """Return product recommendations for the given query.

    The "prompt" here is just the user's free-text search query — there is
    no LLM call and no template injection point.
    """
    payload = request.get_json(silent=True) or {}
    query = sanitize_query(payload.get("query", ""))
    if not query:
        return jsonify({"error": "query is required"}), 400

    scores = agent.score(query)
    top = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:10]
    response = {"query": query, "results": [{"sku": sku, "score": score} for sku, score in top]}
    return jsonify(truncate_response(response))


@app.route("/api/catalog/<sku>")
def catalog_item(sku):
    """Look up a single catalog item from the upstream catalog service."""
    try:
        upstream = requests.get(
            f"{API_BASE_URL}/items/{sku}",
            timeout=API_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )
        upstream.raise_for_status()
    except requests.RequestException as exc:
        logger.warning("catalog lookup failed for %s: %s", sku, exc)
        return jsonify({"error": "catalog service unavailable"}), 502

    return jsonify(upstream.json())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
