"""Sample web application code for benchmark testing.
Contains patterns that should trigger Python/web security scanners.
"""
import os
import hashlib
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# SQL injection vulnerability
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)


# Command injection
@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result


# XSS via template string
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    return render_template_string(f"<h1>Hello {name}!</h1>")


# Weak cryptography
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# Hardcoded secret
SECRET_KEY = "super-secret-key-do-not-share"
DATABASE_URL = "postgresql://admin:password123@localhost:5432/mydb"


# Path traversal
@app.route('/download')
def download():
    filename = request.args.get('file')
    return open(f"/var/data/{filename}", 'rb').read()


# SSRF
@app.route('/fetch')
def fetch_url():
    import requests
    url = request.args.get('url')
    return requests.get(url).text


# Insecure deserialization
import pickle
def load_data(data):
    return pickle.loads(data)
