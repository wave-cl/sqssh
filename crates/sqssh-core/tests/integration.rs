//! Integration tests for sqssh suite.
//!
//! These tests generate temp keys, start sqsshd on a random port,
//! and exercise the client tools. Requires the binaries to be built.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/
    path.pop(); // workspace root
    path.push("target");
    path.push("debug");
    path.push(name);
    path
}

struct TestEnv {
    dir: tempfile::TempDir,
    port: u16,
    server_pid: Option<u32>,
}

impl TestEnv {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();

        // Generate server host key
        let host_key = dir.path().join("host_key");
        let status = Command::new(bin_path("sqssh-keygen"))
            .args(["-f", host_key.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
        // Keygen prompts for passphrase — pipe empty line
        assert!(status.success() || host_key.exists());

        // Generate client key (no passphrase)
        let client_key = dir.path().join("id_ed25519");
        let mut child = Command::new(bin_path("sqssh-keygen"))
            .args(["-f", client_key.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Send empty passphrase
        if let Some(ref mut stdin) = child.stdin {
            use std::io::Write;
            writeln!(stdin).ok();
        }
        child.wait().unwrap();

        // Find a random available port
        let port = {
            let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.local_addr().unwrap().port()
        };

        TestEnv {
            dir,
            port,
            server_pid: None,
        }
    }

    fn host_key_path(&self) -> PathBuf {
        self.dir.path().join("host_key")
    }

    fn client_key_path(&self) -> PathBuf {
        self.dir.path().join("id_ed25519")
    }

    fn client_pubkey_path(&self) -> PathBuf {
        self.dir.path().join("id_ed25519.pub")
    }

    fn authorized_keys_path(&self) -> PathBuf {
        self.dir.path().join("authorized_keys")
    }

    fn setup_authorized_keys(&self) {
        let pubkey = std::fs::read_to_string(self.client_pubkey_path()).unwrap();
        std::fs::write(self.authorized_keys_path(), &pubkey).unwrap();
    }

    fn server_pubkey(&self) -> String {
        let output = Command::new(bin_path("sqsshd"))
            .args(["--host-key", self.host_key_path().to_str().unwrap(), "--show-pubkey"])
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn known_hosts_path(&self) -> PathBuf {
        self.dir.path().join("known_hosts")
    }

    fn setup_known_hosts(&self) {
        let pubkey = self.server_pubkey();
        let content = format!("127.0.0.1 {pubkey}\n");
        std::fs::write(self.known_hosts_path(), content).unwrap();
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if let Some(pid) = self.server_pid {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
}

#[test]
fn test_keygen_creates_keypair() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("test_key");

    let mut child = Command::new(bin_path("sqssh-keygen"))
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
    assert!(key_path.with_extension("pub").exists(), "public key should exist");

    let content = std::fs::read_to_string(&key_path).unwrap();
    assert!(content.starts_with("SQSSH-ED25519-PRIVATE-KEY"));
}

#[test]
fn test_keygen_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("enc_key");

    let mut child = Command::new(bin_path("sqssh-keygen"))
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
    let mut child = Command::new(bin_path("sqssh-keygen"))
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
    let output = Command::new(bin_path("sqssh-keygen"))
        .args(["--fingerprint", key_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let fp = String::from_utf8(output.stdout).unwrap();
    assert!(!fp.trim().is_empty());
}

#[test]
fn test_key_roundtrip() {
    use sqssh_core::keys;

    let (signing, verifying) = keys::generate_keypair();
    let encoded = keys::encode_pubkey(&verifying);
    let decoded = keys::decode_pubkey(&encoded).unwrap();
    assert_eq!(verifying, decoded);
}

#[test]
fn test_encrypted_key_roundtrip() {
    use sqssh_core::keys;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test_enc");

    let (signing, _) = keys::generate_keypair();

    // Save encrypted
    keys::save_private_key_with_passphrase(&path, &signing, Some("mypass")).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.starts_with("SQSSH-ED25519-ENCRYPTED-KEY"));

    // Load with correct passphrase
    let loaded = keys::load_private_key_with_passphrase(&path, "mypass").unwrap();
    assert_eq!(signing.to_bytes(), loaded.to_bytes());

    // Load with wrong passphrase should fail
    assert!(keys::load_private_key_with_passphrase(&path, "wrong").is_err());
}

#[test]
fn test_known_hosts_roundtrip() {
    use sqssh_core::keys;
    use sqssh_core::known_hosts::KnownHosts;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");

    let (_, vk) = keys::generate_keypair();

    let mut kh = KnownHosts::load(&path).unwrap();
    kh.add("test.example.com", vk, "test");
    kh.save(&path).unwrap();

    let kh2 = KnownHosts::load(&path).unwrap();
    let found = kh2.lookup("test.example.com").unwrap();
    assert_eq!(found, &vk);
}

#[test]
fn test_config_parse() {
    use sqssh_core::config::ClientConfig;

    let config = ClientConfig::parse("
        Port 4022
        User testuser

        Host dev
            HostName dev.example.com
            User alice
    ")
    .unwrap();

    let resolved = config.resolve("dev");
    assert_eq!(resolved.hostname.as_deref(), Some("dev.example.com"));
    assert_eq!(resolved.user.as_deref(), Some("alice"));
    assert_eq!(resolved.port, 4022);
}

#[test]
fn test_server_config_parse() {
    use sqssh_core::auth::AuthMode;
    use sqssh_core::config::ServerConfig;

    let config = ServerConfig::parse("
        Port 4022
        AuthMode open+user
        MaxSessions 128
        MaxAuthTries 3
        AllowUsers root admin
        PrintMotd no
    ")
    .unwrap();

    assert_eq!(config.port, 4022);
    assert_eq!(config.auth_mode, AuthMode::OpenAndUser);
    assert_eq!(config.max_sessions, 128);
    assert_eq!(config.max_auth_tries, 3);
    assert_eq!(config.allow_users, vec!["root", "admin"]);
    assert!(!config.print_motd);
}
