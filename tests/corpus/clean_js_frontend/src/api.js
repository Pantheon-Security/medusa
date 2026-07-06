// Small API client for the clean_js_frontend fixture.
// Normal fetch-based requests; no eval/innerHTML, no template injection.

const API_BASE = import.meta.env.VITE_API_BASE_URL || "https://catalog.internal.example.com";

export async function fetchRecommendations(query) {
  const response = await fetch(`${API_BASE}/api/recommend`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });

  if (!response.ok) {
    throw new Error(`Recommendation request failed: ${response.status}`);
  }

  return response.json();
}

export async function fetchCatalogItem(sku) {
  const response = await fetch(`${API_BASE}/api/catalog/${encodeURIComponent(sku)}`);
  if (!response.ok) {
    throw new Error(`Catalog lookup failed: ${response.status}`);
  }
  return response.json();
}
