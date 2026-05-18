"""
Vulnerable Model Serving Script — FOR DEMONSTRATION ONLY.

Vulnerabilities:
- Loading models via pickle (RCE)
- No model signature verification
- Accepting model URLs from user input
- No input validation on inference requests
"""

import os
import pickle
import urllib.request
from pathlib import Path

from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABILITY: Loading model from untrusted pickle file
MODEL_PATH = os.environ.get("MODEL_PATH", "/models/production/model.pkl")


def load_model(path):
    """VULNERABILITY: pickle.load on potentially tampered model file."""
    with open(path, "rb") as f:
        return pickle.load(f)


model = None


@app.route("/predict", methods=["POST"])
def predict():
    """VULNERABILITY: No input validation on inference data."""
    global model
    if model is None:
        model = load_model(MODEL_PATH)

    data = request.json.get("input")
    # No schema validation, no size limits, no type checking
    result = model.predict(data)
    return jsonify({"prediction": result.tolist()})


@app.route("/model/update", methods=["POST"])
def update_model():
    """
    VULNERABILITY: Download and load model from arbitrary URL.
    Combines SSRF + unsafe deserialization.
    """
    global model
    model_url = request.json.get("url")

    # VULNERABILITY: SSRF — fetching arbitrary URLs
    local_path = "/tmp/new_model.pkl"
    urllib.request.urlretrieve(model_url, local_path)

    # VULNERABILITY: Loading untrusted pickle (RCE)
    model = load_model(local_path)
    return jsonify({"status": "model updated"})


@app.route("/model/eval", methods=["POST"])
def eval_model():
    """
    VULNERABILITY: exec() on user-provided evaluation code.
    """
    eval_code = request.json.get("code")
    namespace = {"model": model, "result": None}

    # VULNERABILITY: Arbitrary code execution
    exec(eval_code, namespace)
    return jsonify({"result": str(namespace.get("result"))})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
