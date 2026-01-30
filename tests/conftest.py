#!/usr/bin/env python3
"""
Pytest fixtures for MEDUSA test suite
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any

from medusa.core.licensing import LicenseTier, LicenseInfo


@pytest.fixture
def free_license() -> LicenseInfo:
    """Returns FREE tier license info"""
    return LicenseInfo(
        tier=LicenseTier.FREE,
        email=None,
        organization=None,
        expires_at=None,
        features=[],
        max_repos=1,
        api_access=False,
        runtime_filters=False,
        custom_rules=False
    )


@pytest.fixture
def pro_license() -> LicenseInfo:
    """Returns PRO tier license info"""
    return LicenseInfo(
        tier=LicenseTier.PROFESSIONAL,
        email="test@example.com",
        organization="Test Corp",
        expires_at=datetime.now() + timedelta(days=365),
        features=['runtime_filters', 'api_access', 'webhooks'],
        max_repos=10,
        api_access=True,
        runtime_filters=True,
        custom_rules=False
    )


@pytest.fixture
def enterprise_license() -> LicenseInfo:
    """Returns ENTERPRISE tier license info"""
    return LicenseInfo(
        tier=LicenseTier.ENTERPRISE,
        email="admin@enterprise.com",
        organization="Enterprise Corp",
        expires_at=datetime.now() + timedelta(days=730),
        features=['runtime_filters', 'api_access', 'webhooks', 'custom_rules', 'sso', 'audit_logs'],
        max_repos=-1,  # Unlimited
        api_access=True,
        runtime_filters=True,
        custom_rules=True
    )


@pytest.fixture
def expired_pro_license() -> LicenseInfo:
    """Returns expired PRO license"""
    return LicenseInfo(
        tier=LicenseTier.PROFESSIONAL,
        email="expired@example.com",
        organization="Expired Corp",
        expires_at=datetime.now() - timedelta(days=1),  # Expired yesterday
        features=['runtime_filters', 'api_access'],
        max_repos=10,
        api_access=True,
        runtime_filters=True,
        custom_rules=False
    )


@pytest.fixture
def temp_license_file(tmp_path) -> Path:
    """Creates temporary license.json file"""
    license_file = tmp_path / "license.json"
    license_data = {
        "tier": "professional",
        "email": "test@example.com",
        "organization": "Test Org",
        "expires_at": (datetime.now() + timedelta(days=365)).isoformat()
    }
    with open(license_file, 'w') as f:
        json.dump(license_data, f)
    return license_file


@pytest.fixture
def temp_free_license_file(tmp_path) -> Path:
    """Creates temporary FREE tier license file"""
    license_file = tmp_path / "license.json"
    license_data = {
        "tier": "free"
    }
    with open(license_file, 'w') as f:
        json.dump(license_data, f)
    return license_file


@pytest.fixture
def sample_rules():
    """Returns sample Rule objects for testing"""
    from medusa.rules import Rule, RuleSeverity

    return [
        Rule(
            id="test-sql-injection",
            name="SQL Injection Pattern",
            severity=RuleSeverity.CRITICAL,
            category="injection",
            patterns=[r'SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+.*\+.*'],
            message="Potential SQL injection detected",
            description="String concatenation in SQL query",
            cwe="CWE-89"
        ),
        Rule(
            id="test-prompt-injection",
            name="Prompt Injection",
            severity=RuleSeverity.HIGH,
            category="prompt_injection",
            patterns=[r'ignore\s+previous\s+instructions', r'system:\s*you\s+are'],
            message="Potential prompt injection detected",
            owasp_llm="LLM01"
        ),
        Rule(
            id="test-hardcoded-secret",
            name="Hardcoded Secret",
            severity=RuleSeverity.MEDIUM,
            category="secrets",
            patterns=[r'password\s*=\s*["\'][\w]{8,}["\']'],
            message="Hardcoded password detected"
        )
    ]


@pytest.fixture
def sample_scan_results() -> Dict[str, Any]:
    """Returns sample scan findings"""
    return {
        'findings': [
            {
                'scanner': 'bandit',
                'file': 'src/app.py',
                'line': 42,
                'severity': 'HIGH',
                'confidence': 'HIGH',
                'issue': 'SQL injection vulnerability detected',
                'cwe': '89',
                'code': 'query = f"SELECT * FROM users WHERE id = {user_id}"'
            },
            {
                'scanner': 'gitleaks',
                'file': 'config/settings.py',
                'line': 10,
                'severity': 'CRITICAL',
                'confidence': 'HIGH',
                'issue': 'Hardcoded API key detected',
                'code': 'API_KEY = "sk-1234567890abcdef"'
            },
            {
                'scanner': 'semgrep',
                'file': 'utils/crypto.py',
                'line': 25,
                'severity': 'MEDIUM',
                'confidence': 'MEDIUM',
                'issue': 'Weak cryptographic algorithm (MD5)',
                'code': 'hash = md5(data).hexdigest()'
            }
        ],
        'files_scanned': 42,
        'total_lines_scanned': 5432
    }


@pytest.fixture
def sample_rule_yaml(tmp_path) -> Path:
    """Creates a sample YAML rule file"""
    rule_file = tmp_path / "test_rules.yaml"
    rule_content = """
rules:
  - id: test-rule-001
    name: Test SQL Injection
    severity: HIGH
    category: injection
    patterns:
      - 'SELECT.*WHERE.*='
      - 'INSERT INTO.*VALUES'
    message: SQL injection pattern detected
    cwe: CWE-89

  - id: test-rule-002
    name: Test XSS
    severity: MEDIUM
    category: xss
    pattern: '<script>.*</script>'
    message: Potential XSS vulnerability
"""
    with open(rule_file, 'w') as f:
        f.write(rule_content)
    return rule_file


@pytest.fixture
def sample_runtime_rule_yaml(tmp_path) -> Path:
    """Creates a sample runtime YAML rule file (paid feature)"""
    rule_file = tmp_path / "test_rules_runtime.yaml"
    rule_content = """
rules:
  - id: runtime-rule-001
    name: Advanced Prompt Injection
    severity: CRITICAL
    category: prompt_injection
    patterns:
      - 'ignore previous instructions'
      - 'disregard system prompt'
    message: Advanced prompt injection detected
    owasp_llm: LLM01
"""
    with open(rule_file, 'w') as f:
        f.write(rule_content)
    return rule_file


@pytest.fixture
def vulnerable_code_sample(tmp_path) -> Path:
    """Creates a file with vulnerable code"""
    code_file = tmp_path / "vulnerable.py"
    code = '''
import os

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
password = "MySecretPassword123"

def get_user(user_id):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute(query)

def hash_password(pwd):
    # Weak crypto
    import hashlib
    return hashlib.md5(pwd.encode()).hexdigest()
'''
    with open(code_file, 'w') as f:
        f.write(code)
    return code_file


@pytest.fixture
def clean_code_sample(tmp_path) -> Path:
    """Creates a file with clean, secure code"""
    code_file = tmp_path / "clean.py"
    code = '''
import os
from cryptography.fernet import Fernet

# Proper secret management
API_KEY = os.environ.get('API_KEY')

def get_user(user_id: int):
    # Parameterized query (safe from SQL injection)
    query = "SELECT * FROM users WHERE id = ?"
    return execute_safe(query, (user_id,))

def hash_password(pwd: str) -> str:
    # Strong crypto
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    return ph.hash(pwd)
'''
    with open(code_file, 'w') as f:
        f.write(code)
    return code_file
