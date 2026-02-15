FROM ubuntu:latest

# Running as root (security issue)
USER root

# Hardcoded secrets in environment
ENV DATABASE_PASSWORD=mysecretpassword
ENV API_KEY=sk-1234567890abcdef

# Installing with no version pinning
RUN apt-get update && apt-get install -y \
    python3 \
    curl \
    wget

# Downloading arbitrary scripts
RUN curl -sSL https://example.com/install.sh | bash

# Exposing unnecessary ports
EXPOSE 22 80 443 3306 5432 8080 9090

# World-writable directory
RUN chmod 777 /tmp/app

COPY . /app
WORKDIR /app

# Running as root with broad command
CMD ["python3", "app.py"]
