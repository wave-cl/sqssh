use std::fs;
use std::path::{Path, PathBuf};

use crate::auth::AuthMode;
use crate::error::{Error, Result};
use crate::protocol::DEFAULT_PORT;

/// A parsed host configuration block.
#[derive(Debug, Clone)]
pub struct HostConfig {
    pub pattern: String,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub identity_file: Option<String>,
    pub host_key: Option<String>,
    pub proxy_jump: Option<String>,
    pub local_forwards: Vec<ForwardSpec>,
    pub remote_forwards: Vec<ForwardSpec>,
    pub dynamic_forward: Option<u16>,
    pub udp_forwards: Vec<ForwardSpec>,
    pub connect_timeout: Option<u64>,
    pub keepalive_interval: Option<u64>,
    pub strict_host_key_checking: Option<StrictHostKeyChecking>,
    pub connection_migration: Option<bool>,
    /// SIP-29: the sQUIC envelope version to emit.
    ///
    /// Unset means squic's own default, which is version 3 as of squic
    /// v0.20.0 — the version carrying MAC0 (SIP-37). Set it *down*, to 2 or 1,
    /// for a server too old to accept that: a server that does not recognise
    /// the version drops the Initial in silence, so the symptom of aiming too
    /// high is a handshake timeout with no diagnostic.
    ///
    /// Unset stays `None` rather than resolving to a number here, so squic's
    /// default is never silently pinned over. That mistake is how a client kept
    /// emitting version 1 after squic had moved on.
    pub envelope_version: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct ForwardSpec {
    pub bind_addr: String,
    pub bind_port: u16,
    pub target_addr: String,
    pub target_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictHostKeyChecking {
    Yes,
    No,
    Ask,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            pattern: "*".into(),
            hostname: None,
            port: None,
            user: None,
            identity_file: None,
            host_key: None,
            proxy_jump: None,
            local_forwards: Vec::new(),
            remote_forwards: Vec::new(),
            dynamic_forward: None,
            udp_forwards: Vec::new(),
            connect_timeout: None,
            keepalive_interval: None,
            strict_host_key_checking: None,
            connection_migration: None,
            envelope_version: None,
        }
    }
}

/// The full client configuration.
#[derive(Debug, Default)]
pub struct ClientConfig {
    /// Global defaults (directives before any Host block).
    pub defaults: HostConfig,
    /// Per-host configurations.
    pub hosts: Vec<HostConfig>,
}

impl ClientConfig {
    /// Load configuration from a file. Returns default config if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parse configuration from a string.
    pub fn parse(content: &str) -> Result<Self> {
        let mut config = Self::default();
        let mut current: Option<HostConfig> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (key, value) = split_directive(line)?;

            if key.eq_ignore_ascii_case("Host") {
                if let Some(host_config) = current.take() {
                    config.hosts.push(host_config);
                }
                current = Some(HostConfig {
                    pattern: value.to_string(),
                    ..Default::default()
                });
                continue;
            }

            let target = current.as_mut().unwrap_or(&mut config.defaults);
            apply_directive(target, &key, value)?;
        }

        if let Some(host_config) = current {
            config.hosts.push(host_config);
        }

        Ok(config)
    }

    /// Resolve configuration for a given hostname by merging matching Host blocks.
    pub fn resolve(&self, hostname: &str) -> ResolvedConfig {
        let mut resolved = ResolvedConfig::from_defaults(&self.defaults);

        for host in &self.hosts {
            if crate::known_hosts::pattern_matches_pub(&host.pattern, hostname) {
                resolved.merge(host);
            }
        }

        if resolved.hostname.is_none() {
            resolved.hostname = Some(hostname.to_string());
        }

        resolved
    }

    /// `resolve`, with `-o key=value` overrides applied on top.
    ///
    /// Overrides win over both the matched `Host` blocks and the defaults,
    /// which is the whole point of passing one: it is the thing the caller
    /// typed just now, against a config written earlier. They apply whether or
    /// not any `Host` block matched, so `-o hostkey=...` works for a bare
    /// address that appears nowhere in the config — the case it is most wanted
    /// for, and the one that did nothing at all before, because `-o` was
    /// parsed into a `Vec<String>` that nothing ever read.
    pub fn resolve_with(&self, hostname: &str, overrides: &[String]) -> Result<ResolvedConfig> {
        let mut resolved = self.resolve(hostname);
        if overrides.is_empty() {
            return Ok(resolved);
        }
        let mut over = HostConfig::default();
        for o in overrides {
            let (key, value) = o
                .split_once('=')
                .ok_or_else(|| Error::Config(format!("-o expects key=value, got {o:?}")))?;
            apply_directive(&mut over, key.trim(), value.trim())?;
        }
        resolved.merge(&over);
        if resolved.hostname.is_none() {
            resolved.hostname = Some(hostname.to_string());
        }
        Ok(resolved)
    }
}

/// Fully resolved configuration for a specific connection.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub hostname: Option<String>,
    pub port: u16,
    pub user: Option<String>,
    pub identity_file: Option<String>,
    pub host_key: Option<String>,
    pub proxy_jump: Option<String>,
    pub local_forwards: Vec<ForwardSpec>,
    pub remote_forwards: Vec<ForwardSpec>,
    pub dynamic_forward: Option<u16>,
    pub udp_forwards: Vec<ForwardSpec>,
    pub connect_timeout: u64,
    pub keepalive_interval: u64,
    pub strict_host_key_checking: StrictHostKeyChecking,
    pub connection_migration: bool,
    /// `None` means the caller said nothing, so squic's own default applies.
    /// It must NOT be resolved to a number here: pinning one silently
    /// overrides squic's default, which is how a v0.4.0 client kept emitting
    /// version 1 after squic moved its default to version 2.
    pub envelope_version: Option<u8>,
}

impl ResolvedConfig {
    fn from_defaults(defaults: &HostConfig) -> Self {
        Self {
            hostname: defaults.hostname.clone(),
            port: defaults.port.unwrap_or(DEFAULT_PORT),
            user: defaults.user.clone(),
            identity_file: defaults.identity_file.clone(),
            host_key: defaults.host_key.clone(),
            proxy_jump: defaults.proxy_jump.clone(),
            local_forwards: defaults.local_forwards.clone(),
            remote_forwards: defaults.remote_forwards.clone(),
            dynamic_forward: defaults.dynamic_forward,
            udp_forwards: defaults.udp_forwards.clone(),
            connect_timeout: defaults.connect_timeout.unwrap_or(3),
            keepalive_interval: defaults.keepalive_interval.unwrap_or(15),
            strict_host_key_checking: defaults
                .strict_host_key_checking
                .unwrap_or(StrictHostKeyChecking::Yes),
            connection_migration: defaults.connection_migration.unwrap_or(true),
            envelope_version: defaults.envelope_version,
        }
    }

    fn merge(&mut self, host: &HostConfig) {
        // Host-specific values override defaults
        if let Some(ref v) = host.hostname {
            self.hostname = Some(v.clone());
        }
        if let Some(v) = host.port {
            self.port = v;
        }
        if let Some(ref v) = host.user {
            self.user = Some(v.clone());
        }
        if let Some(ref v) = host.identity_file {
            self.identity_file = Some(v.clone());
        }
        if let Some(ref v) = host.host_key {
            self.host_key = Some(v.clone());
        }
        if let Some(ref v) = host.proxy_jump {
            self.proxy_jump = Some(v.clone());
        }
        self.local_forwards
            .extend(host.local_forwards.iter().cloned());
        self.remote_forwards
            .extend(host.remote_forwards.iter().cloned());
        self.udp_forwards.extend(host.udp_forwards.iter().cloned());
        if let Some(v) = host.dynamic_forward {
            self.dynamic_forward.get_or_insert(v);
        }
        if let Some(v) = host.strict_host_key_checking {
            self.strict_host_key_checking = v;
        }
        if let Some(v) = host.connection_migration {
            self.connection_migration = v;
        }
        if host.envelope_version.is_some() {
            self.envelope_version = host.envelope_version;
        }
    }
}

fn split_directive(line: &str) -> Result<(String, &str)> {
    let mut parts = line.splitn(2, |c: char| c.is_whitespace());
    let key = parts
        .next()
        .ok_or_else(|| Error::Config(format!("empty directive: {line}")))?;
    let value = parts
        .next()
        .ok_or_else(|| Error::Config(format!("missing value for directive '{key}'")))?
        .trim();
    Ok((key.to_string(), value))
}

fn apply_directive(target: &mut HostConfig, key: &str, value: &str) -> Result<()> {
    match key.to_ascii_lowercase().as_str() {
        "hostname" => target.hostname = Some(value.to_string()),
        "port" => {
            target.port = Some(
                value
                    .parse()
                    .map_err(|_| Error::Config(format!("invalid port: {value}")))?,
            );
        }
        "user" => target.user = Some(value.to_string()),
        "identityfile" => target.identity_file = Some(value.to_string()),
        "hostkey" => target.host_key = Some(value.to_string()),
        "envelopeversion" => {
            let v: u8 = value
                .parse()
                .map_err(|_| Error::Config(format!("invalid envelope version: {value}")))?;
            if v == 0 {
                // SIP-29 reserves version 0 and forbids emitting it.
                return Err(Error::Config("envelope version 0 is reserved".into()));
            }
            target.envelope_version = Some(v);
        }
        "proxyjump" => target.proxy_jump = Some(value.to_string()),
        "connecttimeout" => {
            target.connect_timeout = Some(
                value
                    .parse()
                    .map_err(|_| Error::Config(format!("invalid timeout: {value}")))?,
            );
        }
        "keepaliveinterval" => {
            target.keepalive_interval = Some(
                value
                    .parse()
                    .map_err(|_| Error::Config(format!("invalid interval: {value}")))?,
            );
        }
        "stricthostkeychecking" => {
            target.strict_host_key_checking = Some(match value.to_lowercase().as_str() {
                "yes" => StrictHostKeyChecking::Yes,
                "no" => StrictHostKeyChecking::No,
                "ask" => StrictHostKeyChecking::Ask,
                _ => return Err(Error::Config(format!("invalid value: {value}"))),
            });
        }
        "connectionmigration" => {
            target.connection_migration = Some(match value.to_lowercase().as_str() {
                "yes" | "true" => true,
                "no" | "false" => false,
                _ => return Err(Error::Config(format!("invalid value: {value}"))),
            });
        }
        "localforward" => target.local_forwards.push(parse_forward_spec(value)?),
        "remoteforward" => target.remote_forwards.push(parse_forward_spec(value)?),
        "udpforward" => target.udp_forwards.push(parse_forward_spec(value)?),
        "dynamicforward" => {
            target.dynamic_forward = Some(
                value
                    .parse()
                    .map_err(|_| Error::Config(format!("invalid port: {value}")))?,
            );
        }
        _ => {
            tracing::warn!("unknown config directive: {key}");
        }
    }
    Ok(())
}

/// Parse a forward spec: "bind_port target_host:target_port" or
/// "bind_addr:bind_port target_host:target_port"
fn parse_forward_spec(value: &str) -> Result<ForwardSpec> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 2 {
        return Err(Error::Config(format!("invalid forward spec: {value}")));
    }

    let (bind_addr, bind_port) = parse_host_port(parts[0])?;
    let (target_addr, target_port) = parse_host_port(parts[1])?;

    Ok(ForwardSpec {
        bind_addr: bind_addr.unwrap_or_else(|| "127.0.0.1".into()),
        bind_port,
        target_addr: target_addr.unwrap_or_else(|| "127.0.0.1".into()),
        target_port,
    })
}

fn parse_host_port(s: &str) -> Result<(Option<String>, u16)> {
    if let Some(colon_pos) = s.rfind(':') {
        let host = &s[..colon_pos];
        let port: u16 = s[colon_pos + 1..]
            .parse()
            .map_err(|_| Error::Config(format!("invalid port in '{s}'")))?;
        if host.is_empty() {
            Ok((None, port))
        } else {
            Ok((Some(host.to_string()), port))
        }
    } else {
        // Just a port number
        let port: u16 = s
            .parse()
            .map_err(|_| Error::Config(format!("invalid port: {s}")))?;
        Ok((None, port))
    }
}

/// Server configuration parsed from /etc/sqssh/sqsshd.conf.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_address: String,
    pub port: u16,
    pub host_key: PathBuf,
    pub auth_mode: AuthMode,
    pub authorized_keys_file: String,
    pub max_sessions: usize,
    pub control_socket: PathBuf,
    pub connection_migration: bool,
    /// SIP-29: the sQUIC envelope versions this server parses. `None` means
    /// the config said nothing, so squic's own default applies — pinning a
    /// list here would silently override it, the same defect that kept clients
    /// on version 1 after squic moved its default. Narrowing it to `[2]`
    /// retires version 1, which a deployment must be able to do or the oldest
    /// envelope ever defined becomes a permanent floor.
    pub accepted_envelope_versions: Option<Vec<u8>>,
    pub allow_users: Vec<String>,
    pub deny_users: Vec<String>,
    pub print_motd: bool,
    pub print_last_log: bool,
    pub banner: Option<PathBuf>,
    pub max_auth_tries: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0".into(),
            port: DEFAULT_PORT,
            host_key: PathBuf::from("/etc/sqssh/host_key"),
            auth_mode: AuthMode::WhitelistAndUser,
            authorized_keys_file: ".sqssh/authorized_keys".into(),
            max_sessions: 64,
            control_socket: PathBuf::from("/var/run/sqssh/control.sock"),
            connection_migration: true,
            accepted_envelope_versions: None,
            allow_users: Vec::new(),
            deny_users: Vec::new(),
            print_motd: true,
            print_last_log: true,
            banner: None,
            max_auth_tries: 6,
        }
    }
}

impl ServerConfig {
    /// Load configuration from a file. Returns default config if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parse configuration from a string.
    pub fn parse(content: &str) -> Result<Self> {
        let mut config = Self::default();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (key, value) = split_directive(line)?;

            match key.to_ascii_lowercase().as_str() {
                "listenaddress" => config.listen_address = value.to_string(),
                "port" => {
                    config.port = value
                        .parse()
                        .map_err(|_| Error::Config(format!("invalid port: {value}")))?;
                }
                "hostkey" => config.host_key = PathBuf::from(value),
                "authmode" => {
                    config.auth_mode = match value.to_lowercase().as_str() {
                        "whitelist+user" => AuthMode::WhitelistAndUser,
                        "whitelist-only" => AuthMode::WhitelistOnly,
                        "open+user" => AuthMode::OpenAndUser,
                        _ => {
                            return Err(Error::Config(format!("invalid auth mode: {value}")));
                        }
                    };
                }
                "acceptedenvelopeversions" => {
                    let mut versions = Vec::new();
                    for part in value.split(',') {
                        let v: u8 = part.trim().parse().map_err(|_| {
                            Error::Config(format!("invalid envelope version: {part}"))
                        })?;
                        if v == 0 {
                            // SIP-29 reserves version 0 and forbids emitting it.
                            return Err(Error::Config("envelope version 0 is reserved".into()));
                        }
                        versions.push(v);
                    }
                    if versions.is_empty() {
                        return Err(Error::Config(
                            "AcceptedEnvelopeVersions needs at least one version".into(),
                        ));
                    }
                    config.accepted_envelope_versions = Some(versions);
                }
                "authorizedkeysfile" => config.authorized_keys_file = value.to_string(),
                "maxsessions" => {
                    config.max_sessions = value
                        .parse()
                        .map_err(|_| Error::Config(format!("invalid max sessions: {value}")))?;
                }
                "controlsocket" => config.control_socket = PathBuf::from(value),
                "connectionmigration" => {
                    config.connection_migration = match value.to_lowercase().as_str() {
                        "yes" | "true" => true,
                        "no" | "false" => false,
                        _ => return Err(Error::Config(format!("invalid value: {value}"))),
                    };
                }
                "allowusers" => {
                    config.allow_users = value.split_whitespace().map(String::from).collect();
                }
                "denyusers" => {
                    config.deny_users = value.split_whitespace().map(String::from).collect();
                }
                "printmotd" => {
                    config.print_motd = match value.to_lowercase().as_str() {
                        "yes" | "true" => true,
                        "no" | "false" => false,
                        _ => return Err(Error::Config(format!("invalid value: {value}"))),
                    };
                }
                "printlastlog" => {
                    config.print_last_log = match value.to_lowercase().as_str() {
                        "yes" | "true" => true,
                        "no" | "false" => false,
                        _ => return Err(Error::Config(format!("invalid value: {value}"))),
                    };
                }
                "banner" => config.banner = Some(PathBuf::from(value)),
                "maxauthtries" => {
                    config.max_auth_tries = value
                        .parse()
                        .map_err(|_| Error::Config(format!("invalid max auth tries: {value}")))?;
                }
                _ => {
                    tracing::warn!("unknown server config directive: {key}");
                }
            }
        }

        Ok(config)
    }
}

/// Apply a resolved host's SIP-29 envelope version to a squic client config.
///
/// Only when the config actually named one. Leaving it alone otherwise is the
/// whole point: resolving an unset directive to a number here would pin a
/// version on top of squic's own default and silently override it, which is
/// how a client kept emitting version 1 after squic had moved to version 2 —
/// and would strand it on 2 now that squic emits 3.
///
/// Shared with the client so a test exercises the mapping the client actually
/// uses, rather than a copy of it that can agree with a broken original.
pub fn apply_client_envelope_version(cfg: &mut squic::Config, resolved: &ResolvedConfig) {
    if let Some(v) = resolved.envelope_version {
        cfg.envelope_version = v;
    }
}

/// Apply a server config's accepted SIP-29 envelope versions to a squic server
/// config, for the same reason and with the same caveat as the client side.
///
/// Unset leaves squic's own default — every version it knows. Narrowing the set
/// is a deployment's own decision, and it is the decision that finally makes
/// the cookie stage silent, since MAC0 exists only on version 3 (SIP-37).
pub fn apply_accepted_envelope_versions(cfg: &mut squic::Config, server: &ServerConfig) {
    if let Some(v) = &server.accepted_envelope_versions {
        cfg.accepted_envelope_versions = v.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let config = ClientConfig::parse(
            "
            Port 4023
            User default_user

            Host dev
                HostName dev.example.com
                Port 4022
                User alice

            Host prod-*
                User deploy
                StrictHostKeyChecking yes
            ",
        )
        .unwrap();

        assert_eq!(config.defaults.port, Some(4023));
        assert_eq!(config.defaults.user.as_deref(), Some("default_user"));
        assert_eq!(config.hosts.len(), 2);
        assert_eq!(config.hosts[0].pattern, "dev");
        assert_eq!(config.hosts[0].hostname.as_deref(), Some("dev.example.com"));
    }

    /// SIP-29: a client emits one envelope version, and choosing it is per
    /// host — a deployment may run servers of different vintages, and a server
    /// that does not accept the version drops the Initial in silence.
    ///
    /// Unset is the interesting case, and the reason this test exists: it must
    /// stay unset so squic's own default applies, whatever that default has
    /// become.
    #[test]
    fn envelope_version_is_unset_by_default_and_is_per_host() {
        let cfg =
            ClientConfig::parse("Host new\n    EnvelopeVersion 2\n\nHost old\n    Port 2222\n")
                .expect("parses");

        assert_eq!(cfg.resolve("new").envelope_version, Some(2));
        // Unset must stay unset. Resolving it to a number here would pin a
        // version on top of squic's own default and silently override it —
        // which is exactly how a client kept emitting version 1 after squic
        // moved its default to version 2, and would now strand it on 2 after
        // squic moved to 3.
        assert_eq!(cfg.resolve("old").envelope_version, None);
        assert_eq!(cfg.resolve("unmentioned").envelope_version, None);
    }

    /// `-o` must reach the connection. It was parsed into a `Vec<String>`
    /// that nothing read, so every override was accepted and discarded —
    /// silently, which is the worst way for an option to not work.
    #[test]
    fn an_override_wins_and_applies_without_a_matching_host() {
        let cfg = ClientConfig::parse("Host ex\n    User root\n    Port 2222\n").expect("parses");

        // Beats a Host block that says otherwise.
        let r = cfg
            .resolve_with("ex", &["user=alice".into()])
            .expect("applies");
        assert_eq!(r.user.as_deref(), Some("alice"));
        assert_eq!(r.port, 2222, "untouched settings survive");

        // And applies where no Host block matches at all — the bare-address
        // case, which is the one an override is most often typed for.
        let r = cfg
            .resolve_with(
                "10.0.0.1",
                &["hostkey=AyEsg3CzX34Yn1PRQu8LsNYVHQiYb7u585ADBaTXUZGL".into()],
            )
            .expect("applies");
        assert_eq!(
            r.host_key.as_deref(),
            Some("AyEsg3CzX34Yn1PRQu8LsNYVHQiYb7u585ADBaTXUZGL")
        );
        assert_eq!(r.hostname.as_deref(), Some("10.0.0.1"));

        // No overrides must behave exactly as `resolve`.
        assert_eq!(
            cfg.resolve_with("ex", &[]).expect("applies").user,
            cfg.resolve("ex").user
        );

        // Malformed overrides are refused rather than ignored.
        assert!(cfg.resolve_with("ex", &["nonsense".into()]).is_err());
        assert!(cfg.resolve_with("ex", &["port=notanumber".into()]).is_err());
    }

    /// A destination naming no user must stay open for the config to fill in.
    #[test]
    fn parse_remote_leaves_an_unspecified_user_unset() {
        use crate::client::parse_remote;

        let bare = parse_remote("ex:/tmp/x").expect("parses");
        assert_eq!(bare.user, None, "config User must still get its chance");
        assert_eq!(bare.host, "ex");
        assert_eq!(bare.path.as_deref(), Some("/tmp/x"));

        let named = parse_remote("root@ex:/tmp/x").expect("parses");
        assert_eq!(named.user.as_deref(), Some("root"));

        // Defaulting to the local username here is what made `sqscp file
        // ex:/tmp/x` authenticate as the wrong user while `sqssh ex` — which
        // resolves separately — authenticated as root from the same config.
        assert_ne!(
            bare.user,
            Some(whoami::username()),
            "must not be pre-filled with the local user"
        );
    }

    /// Version 0 is reserved by SIP-29 and must never be emitted, so it is
    /// refused at the point somebody could write it down.
    #[test]
    fn envelope_version_zero_is_refused() {
        assert!(ClientConfig::parse("Host h\n    EnvelopeVersion 0\n").is_err());
        assert!(ClientConfig::parse("Host h\n    EnvelopeVersion nonsense\n").is_err());
    }

    #[test]
    fn test_resolve_config() {
        let config = ClientConfig::parse(
            "
            Port 4022
            User default

            Host dev
                HostName dev.example.com
                User alice
                HostKey 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqR
            ",
        )
        .unwrap();

        let resolved = config.resolve("dev");
        assert_eq!(resolved.hostname.as_deref(), Some("dev.example.com"));
        assert_eq!(resolved.user.as_deref(), Some("alice"));
        assert_eq!(resolved.port, 4022);

        let resolved = config.resolve("unknown");
        assert_eq!(resolved.hostname.as_deref(), Some("unknown"));
        assert_eq!(resolved.user.as_deref(), Some("default"));
    }
}
