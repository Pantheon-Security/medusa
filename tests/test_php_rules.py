#!/usr/bin/env python3
"""
Tests for the native PHP security ruleset (medusa/rules/php_security/) +
PHPScanner. Calls PHPScanner.scan_file directly (pre-FP-filter) to assert the
patterns fire on crafted vulnerable PHP and stay quiet on clean idioms.
"""
from pathlib import Path

import pytest

from medusa.scanners.php_scanner import PHPScanner


VULN = '''<?php
$res = $mysqli->query("SELECT * FROM users WHERE id = $id");
system("ping " . $_GET['host']);
eval($_POST['code']);
include($_GET['page']);
$data = file_get_contents($_REQUEST['file']);
$obj = unserialize($_COOKIE['session']);
move_uploaded_file($tmp, $_FILES['f']['name']);
echo $_GET['name'];
curl_setopt($ch, CURLOPT_URL, $_GET['url']);
$h = md5($password);
$api_key = "sk_live_realkey9876543210";
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
'''

# Safe, parameterized PHP — must produce ZERO php_security findings.
CLEAN = '''<?php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
$name = htmlspecialchars($_GET['name'], ENT_QUOTES);
echo $name;
$hash = password_hash($password, PASSWORD_DEFAULT);
$token = bin2hex(random_bytes(32));
$cfg = json_decode($payload, true);
require __DIR__ . '/config.php';
'''


def _scan(tmp_path, src, name="x.php"):
    f = tmp_path / name
    f.write_text(src)
    res = PHPScanner().scan_file(f)
    assert res.success
    return {i.rule_id for i in res.issues}


@pytest.mark.parametrize("rule_id", [
    "MEDUSA-PHP-SCAN-001",  # SQLi interpolation
    "MEDUSA-PHP-SCAN-002",  # command exec tainted
    "MEDUSA-PHP-SCAN-004",  # eval dynamic
    "MEDUSA-PHP-SCAN-010",  # LFI/RFI include
    "MEDUSA-PHP-SCAN-011",  # path traversal file op
    "MEDUSA-PHP-SCAN-012",  # unserialize untrusted
    "MEDUSA-PHP-SCAN-013",  # move_uploaded_file
    "MEDUSA-PHP-SCAN-020",  # reflected XSS echo
    "MEDUSA-PHP-SCAN-021",  # SSRF curl
    "MEDUSA-PHP-SCAN-030",  # weak hash
    "MEDUSA-PHP-SCAN-032",  # hardcoded credential
    "MEDUSA-PHP-SCAN-033",  # TLS verify disabled
])
def test_vuln_patterns_fire(tmp_path, rule_id):
    assert rule_id in _scan(tmp_path, VULN)


def test_clean_php_is_silent(tmp_path):
    # Parameterized / encoded / CSPRNG PHP must produce zero php_security findings.
    assert _scan(tmp_path, CLEAN) == set()
