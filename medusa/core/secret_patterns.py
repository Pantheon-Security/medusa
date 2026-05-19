"""Host-secret detection patterns.

Patterns are tuned for low false-positive rate against host artefacts
(AI chat histories, shell histories) where any match is likely a real
credential. Generic patterns (`password=`, bare `Bearer ...`) are
intentionally excluded — they belong in `medusa scan`, not here.

A `SecretPattern` describes one issuer/credential format:
    rule_id      stable identifier for reports and redaction markers
    name         human label ("PyPI API token")
    kind         coarse category (api_key | private_key | session_token)
    issuer       owning service ("pypi", "anthropic", "aws")
    severity     critical (cloud, signing, prod-tier) | high (api keys) | medium
    regex        compiled pattern that matches the credential value
    mask_prefix  characters to retain at the start of a masked render
"""

import re
from dataclasses import dataclass
from typing import List, Pattern

from medusa.scanners.base import Severity


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    name: str
    kind: str
    issuer: str
    severity: Severity
    regex: Pattern[str]
    mask_prefix: int = 8


def _c(p: str) -> Pattern[str]:
    return re.compile(p)


SECRET_PATTERNS: List[SecretPattern] = [
    # --- AI providers -----------------------------------------------------
    SecretPattern(
        rule_id="MEDUSA-SECRET-ANTHROPIC",
        name="Anthropic API key",
        kind="api_key",
        issuer="anthropic",
        severity=Severity.CRITICAL,
        regex=_c(r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,}"),
        mask_prefix=12,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-OPENAI",
        name="OpenAI API key",
        kind="api_key",
        issuer="openai",
        severity=Severity.CRITICAL,
        # Exclude `sk-ant-*` (Anthropic) which would otherwise match the
        # generic `sk-...` shape. Word boundary + lookahead handles both
        # the legacy `sk-...` and modern `sk-proj-...` / `sk-svcacct-...`
        # / `sk-admin-...` formats.
        regex=_c(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{40,}\b"),
        mask_prefix=8,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-HUGGINGFACE",
        name="HuggingFace token",
        kind="api_key",
        issuer="huggingface",
        severity=Severity.HIGH,
        regex=_c(r"\bhf_[A-Za-z0-9]{30,}\b"),
        mask_prefix=6,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-REPLICATE",
        name="Replicate API token",
        kind="api_key",
        issuer="replicate",
        severity=Severity.HIGH,
        regex=_c(r"\br8_[A-Za-z0-9]{37,}\b"),
        mask_prefix=6,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-COHERE",
        name="Cohere API key",
        kind="api_key",
        issuer="cohere",
        severity=Severity.HIGH,
        regex=_c(r"\bco[a-z]?-[A-Za-z0-9]{40,}\b"),
        mask_prefix=6,
    ),

    # --- Package registries ----------------------------------------------
    SecretPattern(
        rule_id="MEDUSA-SECRET-PYPI",
        name="PyPI API token",
        kind="api_key",
        issuer="pypi",
        severity=Severity.CRITICAL,
        regex=_c(r"pypi-AgE[A-Za-z0-9_\-]{50,}"),
        mask_prefix=10,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-NPM",
        name="npm access token",
        kind="api_key",
        issuer="npm",
        severity=Severity.HIGH,
        regex=_c(r"\bnpm_[A-Za-z0-9]{36}\b"),
        mask_prefix=6,
    ),

    # --- Source forges ---------------------------------------------------
    SecretPattern(
        rule_id="MEDUSA-SECRET-GITHUB-PAT",
        name="GitHub personal access token (classic)",
        kind="api_key",
        issuer="github",
        severity=Severity.CRITICAL,
        regex=_c(r"\bghp_[A-Za-z0-9]{36}\b"),
        mask_prefix=6,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-GITHUB-FINEGRAINED",
        name="GitHub fine-grained personal access token",
        kind="api_key",
        issuer="github",
        severity=Severity.CRITICAL,
        regex=_c(r"\bgithub_pat_[A-Za-z0-9_]{80,}\b"),
        mask_prefix=14,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-GITHUB-OAUTH",
        name="GitHub OAuth access token",
        kind="api_key",
        issuer="github",
        severity=Severity.CRITICAL,
        regex=_c(r"\bgho_[A-Za-z0-9]{36}\b"),
        mask_prefix=6,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-GITHUB-APP",
        name="GitHub App token",
        kind="api_key",
        issuer="github",
        severity=Severity.CRITICAL,
        regex=_c(r"\b(?:ghs|ghu)_[A-Za-z0-9]{36}\b"),
        mask_prefix=6,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-GITLAB-PAT",
        name="GitLab personal access token",
        kind="api_key",
        issuer="gitlab",
        severity=Severity.CRITICAL,
        regex=_c(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
        mask_prefix=8,
    ),

    # --- Cloud (AWS / GCP / Azure) ---------------------------------------
    SecretPattern(
        rule_id="MEDUSA-SECRET-AWS-ACCESS-KEY",
        name="AWS access key ID",
        kind="api_key",
        issuer="aws",
        severity=Severity.CRITICAL,
        regex=_c(r"\b(?:AKIA|ASIA|AGPA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        mask_prefix=6,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-GCP-SERVICE-ACCOUNT",
        name="GCP service-account private key",
        kind="private_key",
        issuer="gcp",
        severity=Severity.CRITICAL,
        # Match the start of a service-account JSON key blob — the
        # `private_key_id` field is a stable shape that's hard to spoof.
        regex=_c(r'"private_key_id"\s*:\s*"[a-f0-9]{40}"'),
        mask_prefix=20,
    ),

    # --- Payments / comms -------------------------------------------------
    SecretPattern(
        rule_id="MEDUSA-SECRET-STRIPE-LIVE",
        name="Stripe live secret key",
        kind="api_key",
        issuer="stripe",
        severity=Severity.CRITICAL,
        regex=_c(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
        mask_prefix=10,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-STRIPE-RESTRICTED",
        name="Stripe restricted key",
        kind="api_key",
        issuer="stripe",
        severity=Severity.CRITICAL,
        regex=_c(r"\brk_live_[A-Za-z0-9]{24,}\b"),
        mask_prefix=10,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-SLACK-BOT",
        name="Slack bot/user token",
        kind="api_key",
        issuer="slack",
        severity=Severity.HIGH,
        regex=_c(r"\bxox[bpoa]-\d+-\d+-[A-Za-z0-9]{20,}\b"),
        mask_prefix=8,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-SENDGRID",
        name="SendGrid API key",
        kind="api_key",
        issuer="sendgrid",
        severity=Severity.HIGH,
        regex=_c(r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,}\b"),
        mask_prefix=8,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-TWILIO",
        name="Twilio API key",
        kind="api_key",
        issuer="twilio",
        severity=Severity.HIGH,
        regex=_c(r"\bSK[a-f0-9]{32}\b"),
        mask_prefix=6,
    ),
    SecretPattern(
        rule_id="MEDUSA-SECRET-DISCORD-WEBHOOK",
        name="Discord webhook URL",
        kind="session_token",
        issuer="discord",
        severity=Severity.HIGH,
        regex=_c(r"https://(?:discord(?:app)?\.com|canary\.discord\.com|ptb\.discord\.com)/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,}"),
        mask_prefix=40,
    ),

    # --- Private keys ----------------------------------------------------
    SecretPattern(
        rule_id="MEDUSA-SECRET-PRIVATE-KEY-PEM",
        name="PEM-encoded private key",
        kind="private_key",
        issuer="generic",
        severity=Severity.CRITICAL,
        # Match the BEGIN line — finding even one is enough; the actual
        # key body extraction happens during redaction.
        regex=_c(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
        mask_prefix=12,
    ),
]


# Index by rule_id for fast lookup during purge.
SECRET_PATTERNS_BY_ID = {p.rule_id: p for p in SECRET_PATTERNS}
