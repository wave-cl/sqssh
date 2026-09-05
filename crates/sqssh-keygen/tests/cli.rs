//! CLI tests for sqssh-keygen.
//!
//! These live here rather than in sqssh-core because they invoke the binary.
//! Cargo only builds a package's own binaries for that package's integration
//! tests, so the previous home reached across packages to
//! `target/debug/sqssh-keygen` and only passed when some earlier build had
//! happened to leave one there — it failed on any clean checkout, which is how
//! CI found it. CARGO_BIN_EXE_ is set by Cargo and guaranteed to exist.

use std::process::{Command, Stdio};

fn keygen() -> &'static str {
    env!("CARGO_BIN_EXE_sqssh-keygen")
}

#[test]
fn test_keygen_creates_keypair() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("test_key");

    let mut child = Command::new(keygen())
        .args(["-f", key_path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        writeln!(stdin).ok(); // empty passphrase
    }
    let status = child.wait().unwrap();
    assert!(status.success());

    assert!(key_path.exists(), "private key should exist");
    assert!(
        key_path.with_extension("pub").exists(),
        "public key should exist"
    );

    let content = std::fs::read_to_string(&key_path).unwrap();
    assert!(content.starts_with("SQSSH-ED25519-PRIVATE-KEY"));
}

#[test]
fn test_keygen_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("enc_key");

    let mut child = Command::new(keygen())
        .args(["-f", key_path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        writeln!(stdin, "testpass").ok();
        writeln!(stdin, "testpass").ok();
    }
    let status = child.wait().unwrap();
    assert!(status.success());

    let content = std::fs::read_to_string(&key_path).unwrap();
    assert!(content.starts_with("SQSSH-ED25519-ENCRYPTED-KEY"));
}

#[test]
fn test_keygen_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("fp_key");

    // Generate key
    let mut child = Command::new(keygen())
        .args(["-f", key_path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        writeln!(stdin).ok();
    }
    child.wait().unwrap();

    // Get fingerprint
    let output = Command::new(keygen())
        .args(["--fingerprint", key_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let fp = String::from_utf8(output.stdout).unwrap();
    assert!(!fp.trim().is_empty());
}
