"""
Human-readable names for security taxonomies used in MEDUSA reports.

OWASP LLM Top 10 (2025) names align with medusa/rules/compliance/owasp_llm_2025.yaml.
MITRE ATLAS names are a curated subset; extend MITRE_ATLAS_TECHNIQUE_NAMES as needed.
Official references: https://atlas.mitre.org/ , https://genai.owasp.org/llm-top-10/
"""

from typing import Dict

# OWASP Top 10 for LLM Applications (2025) — category id -> short name
OWASP_LLM_CATEGORY_NAMES: Dict[str, str] = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain Vulnerabilities",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

# MITRE ATLAS technique id -> name (subset; unknown ids return "")
MITRE_ATLAS_TECHNIQUE_NAMES: Dict[str, str] = {
    "AML.T0010": "ML Supply Chain Compromise",
    "AML.T0012": "Evade ML Model",
    "AML.T0018": "Manipulate Model",
    "AML.T0019": "Replicate ML Model",
    "AML.T0020": "Poison Training Data",
    "AML.T0024": "Exfiltration via ML Inference API",
    "AML.T0029": "Denial of ML Service",
    "AML.T0034": "Cost Harvesting",
    "AML.T0040": "Full ML Model Access",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0044": "Invert ML Model",
    "AML.T0048": "External ML Model Access",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak Injection",
    "AML.T0056": "LLM Plugin Compromise",
}


def owasp_llm_display_name(category_id: str) -> str:
    """Return display name for an OWASP LLM category id, or empty string if unknown."""
    if not category_id:
        return ""
    return OWASP_LLM_CATEGORY_NAMES.get(category_id.strip(), "")


def mitre_atlas_display_name(technique_id: str) -> str:
    """Return display name for a MITRE ATLAS technique id, or empty string if unknown."""
    if not technique_id:
        return ""
    base = technique_id.split(",")[0].strip()
    return MITRE_ATLAS_TECHNIQUE_NAMES.get(base, "")
