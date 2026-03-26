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

Override the install directory:
```
SQSSH_INSTALL_DIR=~/bin curl -fsSL https://raw.githubusercontent.com/wave-cl/sqssh/main/install.sh | sh
```

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

## Quick start

### Generate a keypair

```
sqssh-keygen                                    # prompts for optional passphrase
sqssh-keygen -f ~/.sqssh/work                   # custom path
sqssh-keygen --change-passphrase ~/.sqssh/id_ed25519  # change or remove passphrase
```

Creates `~/.sqssh/id_ed25519` and `~/.sqssh/id_ed25519.pub`. Passphrase-protected keys are encrypted with argon2id + chacha20-poly1305.

### Connect to a server

```
sqssh user@host
sqssh -p 4022 user@host
sqssh -i ~/.sqssh/work_key user@host
sqssh user@host ls -la
```

Escape sequences: `~.` disconnect, `~?` help, `~~` literal tilde. Auto-reconnects on network loss without re-prompting for passphrase. Exits cleanly on server shutdown. Default connect timeout: 3 seconds (configurable via `ConnectTimeout`).

**Key resolution order:** `-i` flag → config `IdentityFile` → agent → learned `~/.sqssh/key_map` → default `id_ed25519`. On successful connect, the host→key mapping is saved to `key_map` automatically.

### Copy files

```
sqscp localfile.txt user@host:/remote/path
sqscp user@host:/remote/file.txt ./
sqscp -r -j 16 ./project/ user@host:~/backup/
sqscp -p -l 1000 largefile.bin user@host:/tmp/
```

Flags: `-r` recursive, `-j N` concurrent streams (default 8), `-p` preserve timestamps, `-P port` UDP port, `-l KB/s` bandwidth limit, `-q` quiet, `-v` verbose.

### Run the server

```
sqsshd                          # listen on 0.0.0.0:22/udp
sqsshd --port 4022              # custom port
sqsshd --show-pubkey            # print server public key
sqsshd --auth-mode open+user    # disable whitelist, use authorized_keys only
sqsshd --log-level debug        # trace, debug, info, warn, error
sqsshd --log-file /var/log/sqsshd.log
sqsshd --log-json               # JSON-formatted output
```

Host key: `/etc/sqssh/host_key`. Server config: `/etc/sqssh/sqsshd.conf`.

Handles SIGTERM/SIGINT gracefully — sends SIGHUP to child shells, drains active connections (5s timeout with watchdog), cleans up the control socket, and exits cleanly.

### Zero-downtime restarts

```
kill -USR1 $(pgrep sqsshd)        # persist sessions
sqsshd --port 22                  # start new instance, recovers sessions
```

SIGUSR1 triggers session persistence: PTY master file descriptors are handed off to `sqssh-persist` via SCM_RIGHTS, shell processes survive (they called `setsid`), and the new sqsshd recovers the sessions. Clients auto-reconnect in ~2 seconds and resume where they left off — running processes, tail commands, and terminal state are preserved.

### Manage keys at runtime

```
sqsshctl reload-keys            # reload your own authorized_keys
sqsshctl reload-keys --all      # reload all users (root only)
```

No server restart required. Communicates over Unix socket (`/run/sqssh/control.sock`).

### Key agent

```
eval $(sqssh-agent)              # start agent, set SQSSH_AGENT_SOCK
sqssh-add                        # add default key (~/.sqssh/id_ed25519)
sqssh-add ~/.sqssh/other_key     # add specific key
sqssh-add -l                     # list keys in agent
sqssh-add -D                     # remove all keys
```

When the agent is running, `sqssh` and `sqscp` use it automatically — no `-i` flag needed.

### Deploy keys to a server

```
sqssh-copy-id user@host                      # deploy default public key
sqssh-copy-id -i ~/.sqssh/other.pub user@host  # deploy specific key
```

Appends the key to remote `~/.sqssh/authorized_keys` and triggers `sqsshctl reload-keys`.

### Manage known hosts

Server keys are distributed out-of-band (no TOFU). Use `sqsshd --show-pubkey` on the server, then add it on the client:

```
sqssh-keyscan add host.example.com <base58-pubkey>
sqssh-keyscan list
sqssh-keyscan remove host.example.com
sqssh-keyscan fingerprint <base58-pubkey>
```

### Interactive file transfer

```
sqsftp user@host
sftp> ls
sftp> cd /var/log
sftp> get syslog
sftp> put localfile.txt
sftp> mkdir backups
sftp> stat file.txt
sftp> rename old.txt new.txt
sftp> rm temp.txt
sftp> lpwd
sftp> lcd ~/Downloads
sftp> quit
```

Uses a raw binary protocol on a QUIC bidi stream for navigation and metadata operations, with separate uni streams for file transfers (get/put).

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

sqscp vs OpenSSH scp — server-to-server between two Hetzner VPS (Falkenstein ↔ Helsinki), measured median of 3 runs, all transfers md5-verified.

| Test | sqscp | scp | Winner |
|------|-------|-----|--------|
| 1KB | 749 KB/s | 4.7 KB/s | **sqscp 159x** |
| 10MB | 134 MB/s | 32 MB/s | **sqscp 4.2x** |
| 100MB | 144 MB/s | 171 MB/s | scp 1.2x |
| 1GB | 163 MB/s | 292 MB/s | scp 1.8x |
| 1000 × 1KB j=1 | 9.2 MB/s | 0.4 MB/s | **sqscp 23x** |
| 1000 × 1KB j=4 | 5.8 MB/s | 0.4 MB/s | **sqscp 15x** |
| 1000 × 1KB j=16 | 8.4 MB/s | 0.4 MB/s | **sqscp 21x** |
| 1000 × 1KB j=32 | 10.3 MB/s | 0.4 MB/s | **sqscp 26x** |
| 100 × 1MB j=1 | 141 MB/s | 92 MB/s | **sqscp 1.5x** |
| 100 × 1MB j=4 | 129 MB/s | 92 MB/s | **sqscp 1.4x** |
| 100 × 1MB j=16 | 145 MB/s | 92 MB/s | **sqscp 1.6x** |
| 100 × 1MB j=32 | 127 MB/s | 92 MB/s | **sqscp 1.4x** |

sqscp wins 10 of 12 tests. It dominates on small files (159x faster on 1KB), many-file transfers (26x on 1000 small files), and medium directories (1.6x on 100×1MB). scp wins on large single-file transfers (100MB+) where TCP's congestion control ramps faster over sustained bulk transfer.

File transfers use raw QUIC streams with zero application-layer framing — file bytes go directly on the wire after a minimal header (path, size, mode, timestamps).

## Future

- **Port forwarding** — TCP local (`-L`), TCP remote (`-R`), SOCKS5 dynamic (`-D`), and native UDP forwarding (`-U`). Protocol types already defined.
- **ProxyJump** — bastion host chaining (`sqssh -J bastion user@target`). Config directive already parsed.

## License

MIT
