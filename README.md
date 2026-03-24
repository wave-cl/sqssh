# sqssh

A modern replacement for the OpenSSH suite, built on [sQUIC](https://github.com/wave-cl/squic-rust).

## Why

SSH runs over TCP. sqssh runs over sQUIC, which means:

- **Lower latency** — 0-RTT connection establishment
- **Connection migration** — roam between networks without dropping your session
- **Multiplexed streams** — no head-of-line blocking between channels
- **Silent server** — the server is invisible to unauthenticated scanners (sQUIC whitelisting)

Same port number (22), different protocol (UDP instead of TCP). They coexist.

## Tools

| Tool | Status | Description |
|------|--------|-------------|
| `sqssh` | ✓ | Remote shell and command execution |
| `sqsshd` | ✓ | Server daemon |
| `sqssh-keygen` | ✓ | Ed25519 key generation |
| `sqscp` | — | Secure file copy |
| `sqsftp` | — | SFTP |
| `sqssh-agent` | — | Key agent |
| `sqssh-add` | — | Add keys to agent |
| `sqssh-copy-id` | — | Deploy public keys to remote hosts |
| `sqssh-keyscan` | — | Scan host public keys |
| `sqsshctl` | — | Connection management |

## Quick start

### Generate a keypair

```
sqssh-keygen
```

Creates `~/.sqssh/id_ed25519` and `~/.sqssh/id_ed25519.pub`.

### Connect to a server

```
sqssh user@host
sqssh -p 4022 user@host
sqssh user@host ls -la
```

### Run the server

```
sqsshd                          # listen on 0.0.0.0:22/udp
sqsshd --port 4022              # custom port
sqsshd --show-pubkey            # print server public key
```

Host key is stored at `/etc/sqssh/host_key` (generated on first run).

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

### Supported directives

`Hostname`, `Port`, `User`, `IdentityFile`, `HostKey`, `ProxyJump`, `LocalForward`, `RemoteForward`, `UdpForward`, `DynamicForward`, `ConnectTimeout`, `KeepAliveInterval`, `StrictHostKeyChecking`, `ConnectionMigration`

## Key format

sqssh uses Ed25519 exclusively, with Base58 encoding:

```
# public key
sqssh-ed25519 CEFuAsD7Kn5ABJUb4S2ujJxrasBkpoDJCoaNvnh7qdRu user@host

# private key
SQSSH-ED25519-PRIVATE-KEY
<base58-encoded seed>
```

Known hosts (`~/.sqssh/known_hosts`):

```
host.example.com sqssh-ed25519 CEFuAsD7Kn5ABJUb4S2ujJxrasBkpoDJCoaNvnh7qdRu
*.internal sqssh-ed25519 ...
```

## Protocol

- **Transport:** sQUIC over UDP (default port 22)
- **Crypto:** Ed25519 keys, X25519 key exchange (via sQUIC)
- **Serialization:** MessagePack with length-prefixed framing
- **ALPN:** `sqssh/1`
- **Stream 0:** Control channel (auth, forwarding setup, disconnect)
- **Streams 1+:** Application channels (session, port forwarding)

## Building

```
cargo build --release
```

Binaries are in `target/release/`.

## License

MIT
