#!/usr/bin/env python3
"""
Tests for the native Rust security ruleset (medusa/rules/rust_security/) +
RustScanner. Calls RustScanner.scan_file directly (pre-FP-filter) to assert the
patterns fire on crafted vulnerable Rust and stay quiet on clean idioms — the
precision guarantee that bare `unsafe`/`unwrap`/`as` must NOT trigger.
"""
from pathlib import Path

import pytest

from medusa.scanners.rust_scanner import RustScanner


VULN = '''\
fn f(user: &str, bytes: &[u8], s: &str, name: &str, host: &str, ptr: *const u8, len: usize) {
    let _c = Client::builder().danger_accept_invalid_certs(true).build();
    builder.set_verify(SslVerifyMode::NONE);
    let _ = Command::new("bash").arg("-c").arg(format!("echo {}", user)).output();
    let _a: Foo = bincode::deserialize(bytes).unwrap();
    let _b: Foo = serde_yaml::from_str(s).unwrap();
    let _p: Foo = serde_pickle::from_slice(bytes).unwrap();
    let _ = sqlx::query(&format!("SELECT * FROM users WHERE n = '{}'", name));
    let _x: u64 = unsafe { mem::transmute(name) };
    let _s = unsafe { slice::from_raw_parts(ptr, len) };
    let mut h = Md5::new();
    let key = "supersecretkey1234567890";
    let _ = reqwest::get(&format!("https://{}/api", host));
}
'''

# Idiomatic, safe Rust — the precision killers MUST stay silent here.
CLEAN = '''\
fn safe(items: &[u32], name: &str) -> u32 {
    let total = items.iter().sum::<u32>();      // no findings
    let n = name.parse::<u32>().unwrap();        // bare unwrap -> must NOT fire
    let b = total as u8;                         // `as` cast -> must NOT fire
    let v = unsafe { trusted_ffi_call() };       // bare unsafe block -> must NOT fire
    let _ = Command::new("git");                 // non-shell binary -> must NOT fire
    let _ = serde_json::from_str::<Cfg>(name);   // serde_json (intentionally not a rule)
    let url = "https://api.example.com/v1";      // constant URL -> must NOT fire
    total + n as u32 + b as u32 + v
}
'''


def _scan(tmp_path, src):
    f = tmp_path / "x.rs"
    f.write_text(src)
    res = RustScanner().scan_file(f)
    assert res.success
    return {i.rule_id for i in res.issues}


@pytest.mark.parametrize("rule_id", [
    "MEDUSA-RUST-SCAN-001",  # TLS accept invalid certs
    "MEDUSA-RUST-SCAN-003",  # SslVerifyMode::NONE
    "MEDUSA-RUST-SCAN-010",  # shell interpreter
    "MEDUSA-RUST-SCAN-011",  # arg(format!)
    "MEDUSA-RUST-SCAN-012",  # arg("-c")
    "MEDUSA-RUST-SCAN-020",  # bincode
    "MEDUSA-RUST-SCAN-021",  # serde_yaml
    "MEDUSA-RUST-SCAN-022",  # serde_pickle
    "MEDUSA-RUST-SCAN-030",  # sqlx format!
    "MEDUSA-RUST-SCAN-040",  # transmute
    "MEDUSA-RUST-SCAN-041",  # from_raw_parts
    "MEDUSA-RUST-SCAN-050",  # md5
    "MEDUSA-RUST-SCAN-052",  # hardcoded key
    "MEDUSA-RUST-SCAN-060",  # reqwest ssrf
])
def test_vuln_patterns_fire(tmp_path, rule_id):
    assert rule_id in _scan(tmp_path, VULN)


def test_clean_idioms_are_silent(tmp_path):
    # The whole point: idiomatic safe Rust produces ZERO rust_security findings.
    assert _scan(tmp_path, CLEAN) == set()
