#!/usr/bin/env python3
"""
Regression test: GitLeaks placeholder/example secrets must not surface as findings.

The external GitLeaks rules are laxer than MEDUSA's own secret patterns, so doc
fillers like `sk_live_abc123def456` (12-char body; MEDUSA's stripe pattern needs
{24,}) were slipping through as CRITICAL secrets. _looks_placeholder_secret drops
them while preserving real, high-entropy credentials.
"""
import pytest

from medusa.scanners.gitleaks_scanner import _looks_placeholder_secret, GitLeaksScanner


@pytest.mark.parametrize("secret", [
    "sk_live_abc123def456",          # the real-world FP (sequential body)
    "sk_test_your_api_key_here",     # placeholder keyword
    "AKIAEXAMPLEKEY123456",          # 'example'
    "ghp_replace_with_your_token",   # placeholder keywords
    "my_dummy_secret_value",         # 'dummy'
    "token=changeme",                # 'changeme'
    "abcdefghijklmnop",              # fully sequential body
])
def test_flags_placeholders(secret):
    assert _looks_placeholder_secret(secret) is True


@pytest.mark.parametrize("secret", [
    "REDACTED_STRIPE_DOCS_EXAMPLE_KEY",   # realistic Stripe live key
    "AKIAIOSFODNN7EXAMPLE9Q2Z",           # high-entropy-ish (note: contains EXAMPLE -> flagged)
    "ghp_R8kLm2Qw9Xz4Tn7Vb1Yc6Hd3Fj5Gp0",  # realistic GitHub PAT
    "xoxb-2f9K1pQ7wErT8yU3iO5aS6dF",       # realistic Slack token body
])
def test_keeps_real_secrets(secret):
    # Skip the deliberately-contradictory AWS example (contains literal 'EXAMPLE')
    if "EXAMPLE" in secret:
        assert _looks_placeholder_secret(secret) is True
    else:
        assert _looks_placeholder_secret(secret) is False


def test_parse_finding_drops_placeholder():
    sc = GitLeaksScanner()
    placeholder = {"RuleID": "stripe-access-token", "Description": "Stripe key",
                   "Secret": "sk_live_abc123def456", "Match": "sk_live_abc123def456",
                   "StartLine": 557}
    real = {"RuleID": "stripe-access-token", "Description": "Stripe key",
            "Secret": "REDACTED_STRIPE_DOCS_EXAMPLE_KEY",
            "Match": "REDACTED_STRIPE_DOCS_EXAMPLE_KEY", "StartLine": 12}
    assert sc._parse_finding(placeholder) is None
    assert sc._parse_finding(real) is not None
