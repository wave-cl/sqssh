# sqssh Guide

A walkthrough of the sqssh suite — from first key to production deployment.

## Getting started

### 1. Generate your key

```
sqssh-keygen
```

You'll be prompted for an optional passphrase. This creates `~/.sqssh/id_ed25519` (private) and `~/.sqssh/id_ed25519.pub` (public). Your public key is a Base58-encoded Ed25519 key — short enough to share in a message.

To create a key at a custom path:

```
sqssh-keygen -f ~/.sqssh/work_key -C "work laptop"
```

### 2. Trust the server

sqssh has no TOFU (trust on first use). You need the server's public key before connecting. Get it from the server admin, or if you have SSH access:

```
ssh root@host sqsshd --show-pubkey
```

Then add it locally:

```
sqssh-keyscan add host.example.com <base58-pubkey>
```

### 3. Deploy your key to the server

If sqsshd is already running on the server:

```
sqssh-copy-id user@host
```

Or manually — append your public key to `~/.sqssh/authorized_keys` on the server and run `sqsshctl reload-keys`.

### 4. Connect

```
sqssh user@host
```

That's it. You're in.

## Use cases

### Remote shell

```
sqssh user@host                        # interactive shell
sqssh user@host ls -la /var/log        # run a command
sqssh -T user@host tar czf - ./src     # pipe without PTY
```

Escape sequences while connected:
- `~.` — disconnect immediately
- `~?` — show available escapes
- `~~` — send a literal tilde

The client auto-reconnects on network loss (WiFi switch, VPN reconnect) without re-prompting for your passphrase. If the server shuts down, the client exits cleanly.

### Copying files

Single files:

```
sqscp localfile.txt user@host:/tmp/
sqscp user@host:~/report.pdf ./Downloads/
```

Directories:

```
sqscp -r ./project/ user@host:~/backup/
sqscp -r user@host:/var/log/ ./logs/
```

Parallel transfers for directories (default: 8 concurrent streams):

```
sqscp -j 16 -r ./dataset/ user@host:~/data/
```

Preserve timestamps and limit bandwidth:

```
sqscp -p -l 5000 largefile.bin user@host:/tmp/    # 5 MB/s limit
```

### Interactive file browser

```
sqsftp user@host
```

Commands: `ls`, `cd`, `pwd`, `get`, `put`, `mkdir`, `rm`, `rename`, `stat`, `help`, `quit`. Local commands: `lpwd`, `lcd`, `lls`.

Batch mode:

```
sqsftp -b commands.txt user@host
```

### Setting up a new server

Install sqssh on the server:

```
ssh root@host 'curl -fsSL https://raw.githubusercontent.com/wave-cl/sqssh/main/install.sh | sh -s -- --server'
```

This installs all binaries, generates a host key, creates the systemd service, and starts sqsshd on port 22/UDP. The installer prints the server's public key and next steps.

Then on your machine:

```
sqssh-keyscan add host.example.com <server-pubkey>
sqssh-copy-id root@host
sqssh root@host
```

### Managing a fleet with config

Create `~/.sqssh/config`:

```
Host web-*
    User deploy
    Port 22
    IdentityFile ~/.sqssh/deploy_key

Host web-1
    Hostname 10.0.1.10

Host web-2
    Hostname 10.0.1.11

Host db
    Hostname 10.0.2.5
    User postgres
```

Then connect by alias:

```
sqssh web-1
sqscp -r ./release/ web-1:~/app/
sqsftp db
```

### Using the key agent

Start the agent (add to your shell profile):

```
eval $(sqssh-agent)
```

Add keys:

```
sqssh-add                              # add default key
sqssh-add ~/.sqssh/work_key            # add specific key
sqssh-add -l                           # list loaded keys
```

With the agent running, `sqssh`, `sqscp`, and `sqsftp` use loaded keys automatically — no `-i` flag and no passphrase prompts.

### Zero-downtime server restarts

Upgrade sqsshd without dropping sessions:

```
kill -USR1 $(pgrep sqsshd)       # persist sessions to sqssh-persist
sqsshd --port 22                 # start new instance, recovers sessions
```

Running processes (shells, tail, htop) survive. Clients auto-reconnect in ~2 seconds and resume where they left off. Terminal state, environment, and running commands are preserved.

For systemd:

```
systemctl reload sqsshd          # sends SIGUSR1
```

### Key rotation

Generate a new key and deploy it:

```
sqssh-keygen -f ~/.sqssh/new_key
sqssh-copy-id -i ~/.sqssh/new_key.pub user@host
```

Remove the old key from the server's `~/.sqssh/authorized_keys`, then reload:

```
sqssh user@host 'sqsshctl reload-keys'
```

Change a key's passphrase:

```
sqssh-keygen --change-passphrase ~/.sqssh/id_ed25519
```

### Server administration

Reload authorized keys without restart:

```
sqsshctl reload-keys              # reload your own keys
sqsshctl reload-keys --all        # reload all users (root only)
```

View server logs:

```
journalctl -u sqsshd -f           # follow live logs
```

Show the server's public key:

```
sqsshd --show-pubkey
```

## Tool reference

### sqssh

Remote shell client.

```
sqssh [OPTIONS] <[user@]host> [COMMAND...]
```

| Flag | Long | Description |
|------|------|-------------|
| `-p` | `--port` | UDP port |
| `-i` | `--identity` | Private key file |
| `-l` | `--login-name` | Username |
| `-N` | `--no-command` | No remote command |
| `-n` | `--no-stdin` | Redirect stdin from /dev/null |
| `-T` | `--no-pty` | Disable PTY |
| `-t` | `--force-pty` | Force PTY |
| `-q` | `--quiet` | Suppress warnings |
| `-v` | `--verbose` | Debug logging |
| `-F` | `--config` | Config file path |
| `-e` | `--escape` | Escape character (default: `~`) |
| `-E` | `--log-file` | Log to file |
| `-o` | `--option` | Config option (key=value) |

Key resolution order: `-i` flag, config `IdentityFile`, agent, learned `~/.sqssh/key_map`, default `id_ed25519`.

### sqsshd

Server daemon.

```
sqsshd [OPTIONS]
```

| Flag | Long | Description |
|------|------|-------------|
| `-l` | `--listen` | Listen address |
| `-p` | `--port` | UDP port |
| `-k` | `--host-key` | Host key file |
| `-c` | `--config` | Config file |
| | `--auth-mode` | `whitelist+user`, `whitelist-only`, or `open+user` |
| | `--no-migration` | Disable connection migration |
| | `--show-pubkey` | Print server public key and exit |
| | `--log-level` | trace, debug, info, warn, error |
| | `--log-file` | Log to file |
| | `--log-json` | JSON log format |

Signals: SIGTERM/SIGINT for graceful shutdown (5s drain), SIGUSR1 for session persistence.

### sqscp

Secure file copy with parallel streams.

```
sqscp [OPTIONS] <source...> <destination>
```

| Flag | Long | Description |
|------|------|-------------|
| `-P` | `--port` | UDP port |
| `-i` | `--identity` | Private key file |
| `-r` | `--recursive` | Recursive copy |
| `-p` | `--preserve` | Preserve timestamps |
| `-j` | `--jobs` | Concurrent streams (default: 8) |
| `-l` | `--limit` | Bandwidth limit in KB/s |
| `-q` | `--quiet` | No progress output |
| `-v` | `--verbose` | Debug logging |
| `-F` | `--config` | Config file path |

### sqsftp

Interactive file transfer.

```
sqsftp [OPTIONS] <[user@]host>
```

| Flag | Long | Description |
|------|------|-------------|
| `-p` | `--port` | UDP port |
| `-i` | `--identity` | Private key file |
| `-F` | `--config` | Config file path |
| `-b` | `--batch` | Read commands from file |
| `-q` | `--quiet` | Quiet mode |
| `-v` | `--verbose` | Debug logging |

Commands: `ls`, `cd`, `pwd`, `get`, `put`, `mkdir`, `rmdir`, `rm`, `rename`, `stat`, `chmod`, `help`, `quit`/`exit`/`bye`. Local: `lpwd`, `lcd`, `lls`.

### sqssh-keygen

Key generation and management.

```
sqssh-keygen [OPTIONS]
```

| Flag | Long | Description |
|------|------|-------------|
| `-f` | `--file` | Output file path |
| `-C` | `--comment` | Public key comment |
| `-l` | `--fingerprint` | Show fingerprint of a key file |
| `-I` | `--import-openssh` | Import OpenSSH Ed25519 key |
| `-p` | `--change-passphrase` | Change passphrase of existing key |
| `-N` | `--new-passphrase` | New passphrase (non-interactive) |
| `-y` | `--print-public` | Print public key from private key |
| `-q` | `--quiet` | Quiet mode |

### sqssh-keyscan

Known hosts management.

```
sqssh-keyscan <command>
```

| Command | Description |
|---------|-------------|
| `add <host> <pubkey>` | Add host key to known_hosts |
| `remove <host>` | Remove host |
| `list` | List all known hosts |
| `fingerprint <pubkey>` | Show fingerprint |
| `scan <host>` | Scan remote host for its key |

### sqssh-agent

Key agent daemon.

```
sqssh-agent [OPTIONS]
```

| Flag | Long | Description |
|------|------|-------------|
| `-d` | `--debug` | Run in foreground |
| `-s` | `--socket` | Socket path |
| `-k` | `--kill` | Kill running agent |

### sqssh-add

Manage keys in the agent.

```
sqssh-add [OPTIONS] [KEYS...]
```

| Flag | Long | Description |
|------|------|-------------|
| `-l` | `--list` | List key fingerprints |
| `-L` | `--list-public` | List full public keys |
| `-d` | `--delete` | Remove a specific key |
| `-D` | `--delete-all` | Remove all keys |
| `-q` | `--quiet` | Quiet mode |

### sqssh-copy-id

Deploy public keys to remote hosts.

```
sqssh-copy-id [OPTIONS] <[user@]host>
```

| Flag | Long | Description |
|------|------|-------------|
| `-i` | `--identity` | Public key file to deploy |
| `-p` | `--port` | UDP port |
| `-F` | `--config` | Config file path |
| `-n` | `--dry-run` | Show what would be done |
| `-f` | `--force` | Skip duplicate check |

### sqsshctl

Server control utility.

```
sqsshctl [OPTIONS] <command>
```

| Command | Description |
|---------|-------------|
| `reload-keys` | Reload authorized_keys |
| `reload-keys --all` | Reload all users (root only) |

| Flag | Long | Description |
|------|------|-------------|
| `-s` | `--socket` | Control socket path |

## Files and directories

### Client (`~/.sqssh/`)

| File | Description |
|------|-------------|
| `id_ed25519` | Default private key (mode 0600) |
| `id_ed25519.pub` | Default public key (mode 0644) |
| `known_hosts` | Trusted server keys (mode 0644) |
| `config` | Client configuration |
| `key_map` | Auto-learned host-to-key mappings |
| `agent.sock` | Agent Unix socket (mode 0600) |

### Server (`/etc/sqssh/`)

| File | Description |
|------|-------------|
| `host_key` | Server private key (mode 0600) |
| `host_key.pub` | Server public key |
| `sqsshd.conf` | Server configuration |

### Per-user (server, `~/.sqssh/`)

| File | Description |
|------|-------------|
| `authorized_keys` | Authorized client public keys (mode 0600) |

### Runtime

| File | Description |
|------|-------------|
| `/run/sqssh/control.sock` | sqsshctl control socket (mode 0666) |
| `/run/sqssh/persist.sock` | Session persistence socket |
