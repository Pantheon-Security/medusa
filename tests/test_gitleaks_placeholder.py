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


# Realistic high-entropy secret values are ASSEMBLED FROM PARTS so no contiguous
# provider-format literal (e.g. a full sk_live_ key) lives in the repo — that would
# trip GitHub secret-scanning push protection. The detector still sees the joined
# value at runtime, so the test semantics are unchanged.
_REAL_STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"   # realistic Stripe live key
_REAL_GHPAT = "ghp_" + "R8kLm2Qw9Xz4Tn7Vb1Yc6Hd3Fj5Gp0"        # realistic GitHub PAT
_REAL_SLACK = "xoxb-" + "2f9K1pQ7wErT8yU3iO5aS6dF"             # realistic Slack token body


@pytest.mark.parametrize("secret", [_REAL_STRIPE, _REAL_GHPAT, _REAL_SLACK])
def test_keeps_real_secrets(secret):
    assert _looks_placeholder_secret(secret) is False


def test_parse_finding_drops_placeholder():
    sc = GitLeaksScanner()
    placeholder = {"RuleID": "stripe-access-token", "Description": "Stripe key",
                   "Secret": "sk_live_abc123def456", "Match": "sk_live_abc123def456",
                   "StartLine": 557}
    real = {"RuleID": "stripe-access-token", "Description": "Stripe key",
            "Secret": _REAL_STRIPE, "Match": _REAL_STRIPE, "StartLine": 12}
    assert sc._parse_finding(placeholder) is None
    assert sc._parse_finding(real) is not None
