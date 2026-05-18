# Vulnerable ML Pipeline Dockerfile — FOR DEMONSTRATION ONLY.
#
# Vulnerabilities:
# - Running as root
# - Using latest tag (unpinned)
# - Exposing unnecessary ports
# - Hardcoded credentials
# - No health checks
# - Insecure pip install

FROM python:latest

# VULNERABILITY: Running as root (no USER directive)
# VULNERABILITY: Using 'latest' tag — not reproducible

# VULNERABILITY: Hardcoded credentials as build args (visible in image history)
ARG MODEL_REGISTRY_TOKEN=FAKE-ghp_1234567890abcdef1234567890abcdef12345678
ARG AWS_ACCESS_KEY_ID=AKIAFAKEKEY12345EXAMPLE
ARG AWS_SECRET_ACCESS_KEY=FAKE+wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

ENV MODEL_REGISTRY_TOKEN=${MODEL_REGISTRY_TOKEN}
ENV AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# VULNERABILITY: pip install with --trusted-host bypasses TLS verification
# VULNERABILITY: Installing from untrusted private index
COPY requirements.txt .
RUN pip install --trusted-host pypi.internal.company.com \
    --extra-index-url http://pypi.internal.company.com/simple/ \
    -r requirements.txt

# VULNERABILITY: Copying secrets into the image layer
COPY .env /app/.env
COPY credentials.json /app/credentials.json

COPY . /app/

# VULNERABILITY: Multiple ports exposed unnecessarily
EXPOSE 8080 8443 9090 6006 5555

# VULNERABILITY: No HEALTHCHECK defined
# VULNERABILITY: Running model serving as root with full privileges
CMD ["python", "serve_model.py", "--host", "0.0.0.0", "--port", "8080"]
