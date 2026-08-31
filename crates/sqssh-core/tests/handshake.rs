//! An end-to-end sQUIC handshake between a client and a server configured the
//! way sqssh and sqsshd configure themselves.
//!
//! This is the test that was missing when squic v0.18.0 moved its default
//! envelope version. sqssh v0.4.0 resolved an unset `EnvelopeVersion` to 1 and
//! passed it to squic explicitly, so every default client kept emitting the old
//! version — and a server that had retired it refused them all, silently,
//! minutes after the retirement landed. Nothing here caught it, because nothing
//! here ever connected a client to a server.
//!
//! It deliberately goes through `apply_client_envelope_version` and
//! `apply_accepted_envelope_versions` rather than setting the fields directly.
//! A test that reimplements the mapping agrees with a broken original, which is
//! the failure this suite has room for and not the one it should add.

use sqssh_core::config::{
    apply_accepted_envelope_versions, apply_client_envelope_version, ClientConfig, ServerConfig,
};
use sqssh_core::protocol;
use std::net::SocketAddr;
use std::time::Duration;

/// A squic server config built the way sqsshd builds one, from a parsed
/// `sqsshd.conf`.
fn server_config(text: &str) -> (squic::Config, ServerConfig) {
    let parsed = ServerConfig::parse(text).expect("server config parses");
    let mut cfg = squic::Config {
        alpn_protocols: vec![protocol::ALPN.to_vec()],
        ..Default::default()
    };
    apply_accepted_envelope_versions(&mut cfg, &parsed);
    (cfg, parsed)
}

/// A squic client config built the way sqssh builds one, from a parsed
/// client config resolved for a host.
fn client_config(text: &str, host: &str, seed: &[u8; 32]) -> squic::Config {
    let parsed = ClientConfig::parse(text).expect("client config parses");
    let resolved = parsed.resolve(host);
    let mut cfg = squic::Config {
        alpn_protocols: vec![protocol::ALPN.to_vec()],
        client_key: Some(seed.iter().map(|b| format!("{b:02x}")).collect()),
        handshake_timeout: Some(Duration::from_secs(3)),
        ..Default::default()
    };
    apply_client_envelope_version(&mut cfg, &resolved);
    cfg
}

async fn listen(cfg: squic::Config) -> (squic::ServerListener, SocketAddr, [u8; 32]) {
    let (signing_key, public) = squic::generate_keypair();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = squic::listen(addr, &signing_key, cfg).await.expect("listen");
    let bound = listener.local_addr().expect("local_addr");
    (listener, bound, public)
}

/// Stock client, stock server, one handshake. A smoke test, and not the
/// regression guard — measured, not assumed: reintroducing the v0.4.0 bug
/// (unset resolving to version 1) leaves this passing, because a default
/// server accepts every version it knows and so admits a client pinned to an
/// old one. `a_client_naming_no_version_reaches_a_server_that_kept_only_the_default`
/// is the one with teeth.
///
/// It still earns its place: it is the only thing here that would notice the
/// two sides failing to handshake for any reason other than the envelope.
#[tokio::test]
async fn a_default_client_and_a_default_server_complete_a_handshake() {
    let (server_cfg, _) = server_config("Port 22\n");
    let (listener, addr, server_pub) = listen(server_cfg).await;

    let accepting = tokio::spawn(async move {
        if let Some(incoming) = listener.accept().await {
            let _ = incoming.await;
        }
        listener
    });

    let client = client_config("Host test\n", "test", &[7u8; 32]);
    let conn = squic::dial(addr, &server_pub, client).await;
    assert!(
        conn.is_ok(),
        "a stock client could not reach a stock server: {:?}",
        conn.err()
    );
    drop(conn);
    let _ = accepting.await;
}

/// The v0.4.0 lockout, reproduced as a test rather than as an outage: a server
/// that has retired every version but squic's current default must still admit
/// a client that names none. If the client ever pins a version again, this
/// fails instead of a deployment going dark.
///
/// This is the test with teeth. Narrowing the server to the current default is
/// what gives it any: against a server accepting everything, a client pinned to
/// an old version connects happily and nothing is learned. Verified by
/// reintroducing the bug — this fails, and the stock-to-stock test above does
/// not.
#[tokio::test]
async fn a_client_naming_no_version_reaches_a_server_that_kept_only_the_default() {
    let current = squic::Config::default().envelope_version;
    let (server_cfg, parsed) =
        server_config(&format!("Port 22\nAcceptedEnvelopeVersions {current}\n"));
    assert_eq!(
        parsed.accepted_envelope_versions,
        Some(vec![current]),
        "the directive did not narrow the set, so this proves nothing"
    );
    let (listener, addr, server_pub) = listen(server_cfg).await;

    let accepting = tokio::spawn(async move {
        if let Some(incoming) = listener.accept().await {
            let _ = incoming.await;
        }
        listener
    });

    let client = client_config("Host test\n", "test", &[9u8; 32]);
    let conn = squic::dial(addr, &server_pub, client).await;
    assert!(
        conn.is_ok(),
        "a client that named no version did not emit squic's default, \
         so it is pinning one somewhere: {:?}",
        conn.err()
    );
    drop(conn);
    let _ = accepting.await;
}

/// The negative control. A server that accepts only a version the client is not
/// sending drops the Initial in silence, so the failure is a timeout with no
/// diagnostic — which is what makes the positive cases above worth having, and
/// what proves they can fail at all.
#[tokio::test]
async fn a_retired_version_is_refused_in_silence() {
    let current = squic::Config::default().envelope_version;
    let other = if current == 1 { 2 } else { current - 1 };
    let (server_cfg, _) = server_config(&format!("Port 22\nAcceptedEnvelopeVersions {other}\n"));
    let (listener, addr, server_pub) = listen(server_cfg).await;

    // The client names the version the server has retired.
    let client = client_config(
        &format!("Host test\n    EnvelopeVersion {current}\n"),
        "test",
        &[11u8; 32],
    );
    let conn = squic::dial(addr, &server_pub, client).await;
    assert!(
        conn.is_err(),
        "a server that retired this version admitted it anyway"
    );
    drop(listener);
}
