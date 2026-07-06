"""Small helper utilities used by the clean_python_service fixture."""
import re

_ALLOWED_QUERY_CHARS = re.compile(r"[^a-zA-Z0-9\s\-]")


def sanitize_query(raw_query: str) -> str:
    """Strip anything that isn't alphanumeric/space/hyphen from a search query."""
    if not isinstance(raw_query, str):
        return ""
    cleaned = _ALLOWED_QUERY_CHARS.sub("", raw_query).strip()
    return cleaned[:200]


def truncate_response(response: dict, max_results: int = 10) -> dict:
    """Cap the number of results returned to a client in one response."""
    results = response.get("results", [])
    return {**response, "results": results[:max_results]}
