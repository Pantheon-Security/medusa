// MEDUSA benchmark corpus — crafted vulnerable Rust patterns (one+ per rule family).
// Used to lock in native rust_security detection in the regression baseline.
use md5;
use sha1;
use std::process::Command;
use std::mem;

fn tls_bad() {
    let _c = Client::builder().danger_accept_invalid_certs(true).build();
    let _d = Client::builder().danger_accept_invalid_hostnames(true).build();
    builder.set_verify(SslVerifyMode::NONE);
}

fn cmd_bad(user: &str) {
    let _ = Command::new("bash").arg("-c").arg(format!("echo {}", user)).output();
}

fn deser_bad(bytes: &[u8], s: &str) {
    let _a: Foo = bincode::deserialize(bytes).unwrap();
    let _b: Foo = serde_yaml::from_str(s).unwrap();
    let _c: Foo = serde_pickle::from_slice(bytes, Default::default()).unwrap();
    let _d: Foo = rmp_serde::from_slice(bytes).unwrap();
}

fn sql_bad(name: &str) {
    let _ = sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", name));
    let _ = sql_query(format!("SELECT * FROM t WHERE id = {}", name));
    let _ = conn.execute(&format!("DELETE FROM t WHERE k = '{}'", name));
}

fn mem_bad(ptr: *const u8, len: usize) {
    let _x: u64 = unsafe { mem::transmute(some_value) };
    let _s = unsafe { slice::from_raw_parts(ptr, len) };
    let mut v: Vec<u8> = Vec::with_capacity(len);
    unsafe { v.set_len(len); }
    let _e = unsafe { v.get_unchecked(0) };
}

fn crypto_bad() {
    let mut _h = Md5::new();
    let mut _g = Sha1::new();
    let key = "supersecretkey1234567890";
}

fn ssrf_bad(host: &str) {
    let _ = reqwest::get(&format!("https://{}/api", host));
    let _ = client.get(&format!("http://{}/x", host));
}
