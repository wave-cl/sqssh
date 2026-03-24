# sqssh

A modern replacement for the OpenSSH suite, built on [sQUIC](https://github.com/wave-cl/squic-rust).

## Why

SSH runs over TCP. sqssh runs over sQUIC, which means:

- **Lower latency** — 0-RTT connection establishment
- **Connection migration** — roam between networks without dropping your session
- **Multiplexed streams** — no head-of-line blocking between channels
- **Silent server** — the server is invisible to unauthenticated scanners (sQUIC whitelisting)
- **Parallel file transfers** — sqscp copies multiple files simultaneously over independent streams

Same port number (22), different protocol (UDP instead of TCP). They coexist.

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

### Copy files

```
sqscp localfile.txt user@host:/remote/path
sqscp user@host:/remote/file.txt ./
sqscp -r -j 16 ./project/ user@host:~/backup/
sqscp -P -l 1000 largefile.bin user@host:/tmp/
```

Flags: `-r` recursive, `-j N` concurrent streams (default 8), `-P` preserve timestamps, `-l KB/s` bandwidth limit, `-q` quiet, `-v` verbose.

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

Handles SIGTERM/SIGINT gracefully — drains active connections (30s timeout), cleans up the control socket, and exits cleanly.

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

Uses a persistent command channel for navigation and metadata operations, with separate parallel streams for file transfers (get/put).

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

`ListenAddress`, `Port`, `HostKey`, `AuthMode`, `AuthorizedKeysFile`, `MaxSessions`, `ControlSocket`, `ConnectionMigration`

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
- **Streams 1+:** Application channels (session, file transfer, port forwarding)

## Building

```
cargo build --release
```

Binaries are in `target/release/`.

## Future

- **Port forwarding** — TCP local (`-L`), TCP remote (`-R`), SOCKS5 dynamic (`-D`), and native UDP forwarding (`-U`). Protocol types already defined.
- **ProxyJump** — bastion host chaining (`sqssh -J bastion user@target`). Config directive already parsed.

## License

MIT
