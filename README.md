# sqssh (squish)

A modern replacement for the OpenSSH suite, built on [sQUIC](https://github.com/wave-cl/squic-rust).

## Why

SSH runs over TCP. sqssh runs over sQUIC, which means:

- **Lower latency** — Secure 1-RTT connection establishment, SACK piggybacking
- **Connection migration** — roam between networks without dropping your session
- **Parallel file transfers** — sqscp copies multiple files simultaneously over independent streams
- **Privacy Concious Server** — SSH responds to every connection attempt (banner, key exchange). sqssh drops unknown clients at the packet level
- **No TOFU** — SSH trusts unknown hosts on first connect. sqssh requires the server key upfront. No opportunity for MITM on first connection
- **Base58 keys** — shorter, no confusing /+= characters, easy to share verbally or in chat.

Same port number (22), different protocol (UDP instead of TCP). They coexist.

## Install

```
curl -fsSL https://raw.githubusercontent.com/wave-cl/sqssh/main/install.sh | sh
```

Installs to `/usr/local/bin` (root) or `~/.local/bin` (non-root). Supports Linux and macOS on x86_64 and aarch64.

Server install (generates host key, installs systemd service, starts sqsshd):
```
curl -fsSL https://raw.githubusercontent.com/wave-cl/sqssh/main/install.sh | sh -s -- --server
```

## Tools

| Tool | Status | Description |
|------|--------|-------------|
| `sqssh` | ✓ | Remote shell and command execution |
| `sqsshd` | ✓ | Server daemon with two-layer auth |
| `sqssh-keygen` | ✓ | Ed25519 key generation |
| `sqscp` | ✓ | Parallel secure file copy |
| `sqsshctl` | ✓ | Live key reload without restart |
| `sqssh-agent` | ✓ | Key agent daemon |
| `sqssh-add` | ✓ | Add/list/remove keys in agent |
| `sqssh-copy-id` | ✓ | Deploy public keys to remote hosts |
| `sqssh-keyscan` | ✓ | Manage known hosts |
| `sqsftp` | ✓ | Interactive file transfer |
| `sqssh-persist` | ✓ | PTY fd holder for server restarts |

## Getting started

```
sqssh-keygen                                          # generate your key
sqssh-keyscan add host.example.com <server-pubkey>     # trust the server
sqssh user@host                                        # connect
sqscp -r ./project/ user@host:~/backup/                # copy files
```

See the [full guide](docs/guide.md) for server setup, use cases, and tool reference.

## Authentication

sqssh uses a two-layer authentication model:

**Layer 1 — Transport (sQUIC whitelist):** The server is silent to unknown clients. Only clients whose Ed25519 public key is in the whitelist can even reach the server. Unauthorized traffic is dropped at the MAC layer.

**Layer 2 — User mapping (authorized_keys):** After passing the whitelist, the client's public key is checked against `~/.sqssh/authorized_keys` to determine which user account to map to.

Three auth modes:

| Mode | Description |
|------|-------------|
| `whitelist+user` | Both layers required (default) |
| `whitelist-only` | Whitelist sufficient, no user mapping |
| `open+user` | No whitelist, authorized_keys only (like SSH) |

Ed25519 only. No passwords, no RSA, no ECDSA.

## Configuration

`~/.sqssh/config` uses SSH-style syntax:

```
Host dev
    Hostname 10.0.0.5
    Port 4022
    User admin
    IdentityFile ~/.sqssh/work_key

Host *
    KeepAliveInterval 15
    StrictHostKeyChecking yes
    ConnectionMigration yes
```

### Client directives

`Hostname`, `Port`, `User`, `IdentityFile`, `HostKey`, `ProxyJump`, `LocalForward`, `RemoteForward`, `UdpForward`, `DynamicForward`, `ConnectTimeout`, `KeepAliveInterval`, `StrictHostKeyChecking`, `ConnectionMigration`

### Server directives (`/etc/sqssh/sqsshd.conf`)

`ListenAddress`, `Port`, `HostKey`, `AuthMode`, `AuthorizedKeysFile`, `MaxSessions`, `MaxAuthTries`, `ControlSocket`, `ConnectionMigration`, `AllowUsers`, `DenyUsers`, `PrintMotd`, `PrintLastLog`, `Banner`

## Key format

sqssh uses Ed25519 exclusively, with Base58 encoding:

```
# public key
sqssh-ed25519 CEFuAsD7Kn5ABJUb4S2ujJxrasBkpoDJCoaNvnh7qdRu user@host

# private key (unencrypted)
SQSSH-ED25519-PRIVATE-KEY
<base58-encoded seed>

# private key (passphrase-protected)
SQSSH-ED25519-ENCRYPTED-KEY
<base58-encoded encrypted blob>
```

Passphrase-protected keys use argon2id (KDF) + chacha20-poly1305 (AEAD). Generate with `sqssh-keygen` — it prompts for a passphrase (leave empty for no encryption). Encrypted keys are auto-detected on load and prompt for the passphrase.

Key map (`~/.sqssh/key_map`) — auto-populated on successful connect:

```
167.235.197.87 id_ed25519
prod.example.com work_key
dev.internal id_ed25519
```

Maps hosts to key names (relative to `~/.sqssh/`). Created automatically — no manual editing needed. Also updated by `sqssh-copy-id` when deploying keys.

Known hosts (`~/.sqssh/known_hosts`):

```
host.example.com sqssh-ed25519 CEFuAsD7Kn5ABJUb4S2ujJxrasBkpoDJCoaNvnh7qdRu
*.internal sqssh-ed25519 ...
```

## Protocol

- **Transport:** sQUIC over UDP (default port 22)
- **Crypto:** Ed25519 keys, X25519 key exchange (via sQUIC), argon2id + chacha20-poly1305 for key encryption
- **Serialization:** MessagePack for control channel only; shell, SFTP, and file transfers use raw binary encoding directly on QUIC streams
- **ALPN:** `sqssh/1`
- **Stream 0:** Control channel (auth, disconnect) — msgpack framed
- **Raw bidi streams:** Shell I/O (`0xB0`), shell control (`0xB1`), SFTP sessions (`0xC0`) — binary encoded, no msgpack
- **Uni streams:** File transfers (one QUIC stream per file, zero framing overhead)
- **Framed bidi streams:** Legacy session channel (exec, port forwarding) — msgpack framed

## Building

```
cargo build --release
cargo test                      # run integration tests
```

Binaries are in `target/release/`.

## Deployment

Install binaries and config:

```
sudo cp target/release/sqssh* /usr/local/bin/
sudo mkdir -p /etc/sqssh
sudo cp etc/sqsshd.conf /etc/sqssh/
sqssh-keygen -f /etc/sqssh/host_key   # generate server host key
```

Systemd (included in `etc/sqsshd.service`):

```
sudo cp etc/sqsshd.service /etc/systemd/system/
sudo systemctl enable sqsshd
sudo systemctl start sqsshd
sudo systemctl reload sqsshd    # zero-downtime restart (SIGUSR1)
```

## Benchmarks

sqscp vs OpenSSH scp — server-to-server between two Hetzner VPS (Falkenstein ↔ Helsinki), median of 3 runs, all transfers md5-verified.

**Upload (client → server)**

| Test | sqscp | scp | Winner |
|------|-------|-----|--------|
| 1KB | 1.3 MB/s | 5.4 KB/s | **sqscp 241x** |
| 10MB | 376 MB/s | 40 MB/s | **sqscp 9.4x** |
| 100MB | 169 MB/s | 204 MB/s | scp 1.2x |
| 1GB | 149 MB/s | 161 MB/s | scp 1.1x |
| 1000 × 1KB (j=8) | 15 MB/s | 0.6 MB/s | **sqscp 25x** |
| 100 × 1MB (j=8) | 154 MB/s | 134 MB/s | **sqscp 1.1x** |

**Download (server → client)**

| Test | sqscp | scp | Winner |
|------|-------|-----|--------|
| 1KB | 2.1 MB/s | 5.7 KB/s | **sqscp 368x** |
| 10MB | 164 MB/s | 47 MB/s | **sqscp 3.5x** |
| 100MB | 180 MB/s | 242 MB/s | scp 1.3x |
| 1GB | 192 MB/s | 376 MB/s | scp 2.0x |
| 1000 × 1KB (j=8) | 10 MB/s | 0.5 MB/s | **sqscp 20x** |
| 100 × 1MB (j=8) | 185 MB/s | 130 MB/s | **sqscp 1.4x** |

sqscp wins 8 of 12 tests. Dominates on small files (241-368x faster on 1KB), many-file transfers (20-25x on 1000 small files), and multi-file directories (1.1-1.4x on 100×1MB). scp wins on large single-file transfers (100MB+) where TCP's mature congestion control ramps faster over sustained bulk transfer.

File transfers use raw QUIC streams with zero application-layer framing — file bytes go directly on the wire after a minimal header (path, size, mode, timestamps).

## Future

- **Port forwarding** — TCP local (`-L`), TCP remote (`-R`), SOCKS5 dynamic (`-D`), and native UDP forwarding (`-U`). Protocol types already defined.
- **ProxyJump** — bastion host chaining (`sqssh -J bastion user@target`). Config directive already parsed.

## License

MIT
