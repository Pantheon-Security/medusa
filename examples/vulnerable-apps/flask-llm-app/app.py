"""
Vulnerable Flask LLM Application — FOR DEMONSTRATION ONLY.

This app contains intentional security vulnerabilities that MEDUSA detects:
- Hardcoded API keys
- Prompt injection via unsanitized user input
- Insecure RAG pipeline (no input validation)
- Unsafe deserialization of model artifacts
- SQL injection in vector DB query
- Missing rate limiting on LLM endpoints
"""

import os
import pickle
import sqlite3

from flask import Flask, request, jsonify
import openai
import requests

app = Flask(__name__)

# VULNERABILITY: Hardcoded API key (MEDUSA: secrets detection)
OPENAI_API_KEY = "sk-FAKE-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
openai.api_key = OPENAI_API_KEY

# VULNERABILITY: Hardcoded database credentials
DB_PASSWORD = "SuperSecret123!"
POSTGRES_CONN = "postgresql://admin:SuperSecret123!@prod-db.internal:5432/vectors"

# VULNERABILITY: Debug mode in production
app.config["DEBUG"] = True
app.config["SECRET_KEY"] = "hardcoded-flask-secret-key-do-not-use"


def get_db():
    return sqlite3.connect("vectors.db")


@app.route("/chat", methods=["POST"])
def chat():
    """
    VULNERABILITY: Direct user input passed to LLM without sanitization.
    Allows prompt injection attacks.
    """
    user_message = request.json.get("message", "")

    # No input validation, no sanitization, no length check
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            # VULNERABILITY: Unsanitized user input directly in prompt
            {"role": "user", "content": user_message},
        ],
        # VULNERABILITY: No max_tokens limit — cost abuse possible
    )

    return jsonify({"response": response.choices[0].message.content})


@app.route("/rag/query", methods=["POST"])
def rag_query():
    """
    VULNERABILITY: Insecure RAG pipeline.
    - SQL injection in vector similarity search
    - No document-level access control
    - Retrieved context injected without sanitization
    """
    query = request.json.get("query", "")
    collection = request.json.get("collection", "default")

    db = get_db()

    # VULNERABILITY: SQL injection via string formatting
    cursor = db.execute(
        f"SELECT content, embedding FROM documents WHERE collection = '{collection}' "
        f"ORDER BY similarity(embedding, embed('{query}')) LIMIT 5"
    )

    context_docs = [row[0] for row in cursor.fetchall()]
    context = "\n---\n".join(context_docs)

    # VULNERABILITY: Retrieved documents injected directly into prompt
    # A poisoned document can override system instructions
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "Answer based on the context below."},
            {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {query}"},
        ],
    )

    return jsonify({"answer": response.choices[0].message.content})


@app.route("/rag/ingest", methods=["POST"])
def rag_ingest():
    """
    VULNERABILITY: No validation on ingested documents.
    Allows RAG poisoning — attacker can inject malicious instructions
    into the knowledge base that will be retrieved and executed.
    """
    documents = request.json.get("documents", [])

    db = get_db()
    for doc in documents:
        # No content filtering, no source validation
        db.execute(
            "INSERT INTO documents (content, source, collection) VALUES (?, ?, ?)",
            (doc["content"], doc.get("source", "unknown"), doc.get("collection", "default")),
        )
    db.commit()

    return jsonify({"ingested": len(documents)})


@app.route("/model/load", methods=["POST"])
def load_model():
    """
    VULNERABILITY: Unsafe deserialization of model files.
    pickle.load on untrusted data = arbitrary code execution.
    """
    model_url = request.json.get("model_url", "")

    # VULNERABILITY: SSRF — fetching arbitrary URLs from user input
    response = requests.get(model_url)

    # VULNERABILITY: Deserializing untrusted pickle data (RCE)
    model = pickle.loads(response.content)

    return jsonify({"status": "model loaded", "type": str(type(model))})


@app.route("/model/predict", methods=["POST"])
def predict():
    """
    VULNERABILITY: eval() on user-provided preprocessing expression.
    """
    data = request.json.get("data", [])
    preprocess = request.json.get("preprocess", "lambda x: x")

    # VULNERABILITY: eval() on untrusted input — arbitrary code execution
    transform = eval(preprocess)
    processed = transform(data)

    return jsonify({"result": str(processed)})


@app.route("/admin/logs", methods=["GET"])
def admin_logs():
    """
    VULNERABILITY: No authentication on admin endpoint.
    Exposes sensitive LLM interaction logs.
    """
    db = get_db()
    logs = db.execute("SELECT * FROM chat_logs ORDER BY timestamp DESC LIMIT 100").fetchall()
    return jsonify({"logs": logs})


@app.route("/webhook", methods=["POST"])
def webhook():
    """
    VULNERABILITY: No signature verification on incoming webhooks.
    Trusts external data without validation.
    """
    payload = request.json
    # Directly processing unverified external payload
    action = payload.get("action")
    if action == "retrain":
        os.system(f"python retrain.py --dataset {payload.get('dataset')}")
    return jsonify({"status": "processed"})


if __name__ == "__main__":
    # VULNERABILITY: Binding to all interfaces in debug mode
    app.run(host="0.0.0.0", port=5000, debug=True)
