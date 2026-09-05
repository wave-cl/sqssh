//! Library-level integration tests for sqssh-core.
//!
//! Tests that invoke a binary live in that binary's own package, so Cargo
//! builds it for them.

#[test]
fn test_key_roundtrip() {
    use sqssh_core::keys;

    let (_signing, verifying) = keys::generate_keypair();
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

    let config = ClientConfig::parse(
        "
        Port 4022
        User testuser

        Host dev
            HostName dev.example.com
            User alice
    ",
    )
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

    let config = ServerConfig::parse(
        "
        Port 4022
        AuthMode open+user
        MaxSessions 128
        MaxAuthTries 3
        AllowUsers root admin
        PrintMotd no
    ",
    )
    .unwrap();

    assert_eq!(config.port, 4022);
    assert_eq!(config.auth_mode, AuthMode::OpenAndUser);
    assert_eq!(config.max_sessions, 128);
    assert_eq!(config.max_auth_tries, 3);
    assert_eq!(config.allow_users, vec!["root", "admin"]);
    assert!(!config.print_motd);
}

/// SIP-29 requires that a server be able to refuse an old envelope version, or
/// the oldest one ever defined becomes a permanent floor. Unset leaves squic's
/// own default — every version it knows — because retiring one is a
/// deployment's own decision, and it is the decision that finally makes the
/// cookie stage silent (SIP-37: MAC0 exists only on version 3).
#[test]
fn accepted_envelope_versions_are_unset_by_default_and_can_be_narrowed() {
    use sqssh_core::config::ServerConfig;

    // Unset must stay unset, so squic's own default applies. Pinning a list
    // here would silently override it.
    let unset = ServerConfig::parse("Port 22\n").unwrap();
    assert_eq!(unset.accepted_envelope_versions, None);

    let retired = ServerConfig::parse("AcceptedEnvelopeVersions 2\n").unwrap();
    assert_eq!(retired.accepted_envelope_versions, Some(vec![2]));

    let listed = ServerConfig::parse("AcceptedEnvelopeVersions 1, 2\n").unwrap();
    assert_eq!(listed.accepted_envelope_versions, Some(vec![1, 2]));

    // Version 0 is reserved by SIP-29, and a set that parses to nothing would
    // silently block every caller.
    assert!(ServerConfig::parse("AcceptedEnvelopeVersions 0\n").is_err());
    assert!(ServerConfig::parse("AcceptedEnvelopeVersions x\n").is_err());
}
