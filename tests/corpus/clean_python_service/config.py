"""Configuration loading for the clean_python_service fixture.

All secrets come from the environment; nothing is hardcoded.
"""
import os


class Config:
    CATALOG_API_URL = os.environ.get("CATALOG_API_URL", "https://catalog.internal.example.com")
    MODEL_PATH = os.environ.get("MODEL_PATH", "models/recommender.pkl")
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    REQUEST_TIMEOUT_SECONDS = int(os.environ.get("REQUEST_TIMEOUT_SECONDS", "5"))
