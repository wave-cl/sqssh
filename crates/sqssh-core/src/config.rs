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
            connect_timeout: defaults.connect_timeout.unwrap_or(10),
            keepalive_interval: defaults.keepalive_interval.unwrap_or(15),
            strict_host_key_checking: defaults
                .strict_host_key_checking
                .unwrap_or(StrictHostKeyChecking::Yes),
            connection_migration: defaults.connection_migration.unwrap_or(true),
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
        self.local_forwards.extend(host.local_forwards.iter().cloned());
        self.remote_forwards.extend(host.remote_forwards.iter().cloned());
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
            control_socket: PathBuf::from("/run/sqssh/control.sock"),
            connection_migration: true,
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
