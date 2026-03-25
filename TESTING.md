# sqssh Test Plan

Comprehensive manual test plan covering every feature and code path of the sqssh suite. Requires two servers with sqsshd running and a client machine with all binaries installed.

## Prerequisites

```
# Server A: sqsshd running, accessible via SSH for setup
SERVER_A=user@server-a

# Server B: sqsshd running (used for server-to-server and benchmark tests)
SERVER_B=user@server-b

# Verify all binaries are installed and respond to --help
for bin in sqssh sqscp sqsftp sqssh-keygen sqssh-agent sqssh-add sqssh-copy-id sqssh-keyscan sqsshctl; do
  $bin --help > /dev/null 2>&1 && echo "$bin: OK" || echo "$bin: MISSING"
done
```

---

## 1. Key Generation (sqssh-keygen)

### 1.1 Generate unencrypted keypair
```
sqssh-keygen -f /tmp/test_key
cat /tmp/test_key        # Should show: SQSSH-ED25519-PRIVATE-KEY
cat /tmp/test_key.pub    # Should show: sqssh-ed25519 <base58> <comment>
```

### 1.2 Generate encrypted keypair
```
sqssh-keygen -f /tmp/test_key_enc
# Enter passphrase when prompted
cat /tmp/test_key_enc    # Should show: SQSSH-ED25519-ENCRYPTED-KEY
```

### 1.3 Change passphrase
```
sqssh-keygen --change-passphrase /tmp/test_key_enc
# Enter old passphrase, then new passphrase
```

### 1.4 Remove passphrase
```
sqssh-keygen --change-passphrase /tmp/test_key_enc
# Enter old passphrase, leave new passphrase empty
cat /tmp/test_key_enc    # Should show: SQSSH-ED25519-PRIVATE-KEY (now unencrypted)
```

### 1.5 Show fingerprint
```
sqssh-keygen --fingerprint /tmp/test_key.pub
# Should show: SHA256:<hash> <comment>
```

### 1.6 Custom comment
```
sqssh-keygen -f /tmp/test_key_comment -C "work laptop"
grep "work laptop" /tmp/test_key_comment.pub
# Should match
```

### 1.7 Default key location
```
# Without -f, should create ~/.sqssh/id_ed25519 (prompt to overwrite if exists)
sqssh-keygen
```

### 1.8 Import OpenSSH key (if implemented)
```
sqssh-keygen --import-openssh ~/.ssh/id_ed25519
```

### 1.9 File permissions
```
stat -f "%Lp" /tmp/test_key       # Should be 600 (owner read/write only)
stat -f "%Lp" /tmp/test_key.pub   # Should be 644 (world readable)
stat -f "%Lp" ~/.sqssh             # Should be 700 (owner only)
```

---

## 2. Known Hosts Management (sqssh-keyscan)

### 2.1 Add a host
```
PUBKEY=$(ssh $SERVER_A "sqsshd --show-pubkey")
sqssh-keyscan add server-a.example.com $PUBKEY
```

### 2.2 List known hosts
```
sqssh-keyscan list
# Should show: server-a.example.com <pubkey>
```

### 2.3 Show fingerprint
```
sqssh-keyscan fingerprint $PUBKEY
```

### 2.4 Remove a host
```
sqssh-keyscan remove server-a.example.com
sqssh-keyscan list    # Should not show server-a.example.com
```

### 2.5 Wildcard host patterns
```
sqssh-keyscan add "*.internal" $PUBKEY
sqssh-keyscan list    # Should show *.internal
sqssh-keyscan remove "*.internal"
```

---

## 3. Key Deployment (sqssh-copy-id)

### 3.1 Deploy default key
```
sqssh-copy-id $SERVER_A
# Should append pubkey to remote ~/.sqssh/authorized_keys
# Should trigger sqsshctl reload-keys
```

### 3.2 Deploy specific key
```
sqssh-copy-id -i /tmp/test_key.pub $SERVER_A
```

### 3.3 Verify idempotency
```
sqssh-copy-id $SERVER_A
# Should report key already exists, not duplicate it
```

### 3.4 Custom port
```
sqssh-copy-id -p 4022 $SERVER_A
```

### 3.5 Remote permissions after deployment
```
ssh $SERVER_A "stat -c '%a' ~/.sqssh"                # Should be 700
ssh $SERVER_A "stat -c '%a' ~/.sqssh/authorized_keys" # Should be 600
```

---

## 4. Interactive Shell (sqssh)

### 4.1 Basic connection
```
sqssh $SERVER_A
# Should show last login and MOTD, then shell prompt
exit
```

### 4.2 Connection with passphrase-protected key
```
sqssh -i ~/.sqssh/id_ed25519 $SERVER_A
# Should prompt for passphrase
exit
```

### 4.3 Remote command execution
```
sqssh $SERVER_A "echo hello"
# Should print "hello" and exit
echo $?    # Should be 0
```

### 4.4 Remote command exit code
```
sqssh $SERVER_A "exit 42"
echo $?    # Should be 42
```

### 4.5 Remote command with stderr
```
sqssh $SERVER_A "echo err >&2; echo out"
# Should show both stdout and stderr
```

### 4.6 PTY allocation — interactive programs
```
sqssh $SERVER_A
htop        # Should render correctly
# Press q to quit htop
exit
```

### 4.7 Ctrl+C handling
```
sqssh $SERVER_A
sleep 100
# Press Ctrl+C — should interrupt sleep, not kill sqssh
exit
```

### 4.8 Window resize
```
sqssh $SERVER_A
# Resize terminal window
stty size    # Should reflect new dimensions
exit
```

### 4.9 Escape: disconnect (~.)
```
sqssh $SERVER_A
# Press Enter, then ~.
# Should disconnect immediately with "Connection to remote closed."
```

### 4.10 Escape: help (~?)
```
sqssh $SERVER_A
# Press Enter, then ~?
# Should show escape sequence help listing
```

### 4.11 Escape: literal tilde (~~)
```
sqssh $SERVER_A
# Press Enter, then ~~
# Should send a single ~ to the remote shell
```

### 4.12 Custom port
```
sqssh -p 4022 $SERVER_A
```

### 4.13 Verbose mode
```
sqssh -v $SERVER_A
# Should show debug logging
exit
```

### 4.14 Connection timeout (unreachable host)
```
time sqssh user@192.0.2.1
# Should timeout in ~3 seconds with clear error message
```

### 4.15 Unknown host rejection
```
sqssh user@unknown.example.com
# Should fail with "no server key" error
```

### 4.16 Key resolution: agent
```
# With agent running and key loaded, connect without -i
sqssh $SERVER_A
# Should connect using agent key, no passphrase prompt
```

### 4.17 Key resolution: key_map auto-learn
```
cat ~/.sqssh/key_map
# Should show host-to-key mappings for previously connected hosts
```

### 4.18 Specific identity file
```
sqssh -i /tmp/test_key $SERVER_A
```

---

## 5. File Copy (sqscp)

### 5.1 Upload single file
```
dd if=/dev/urandom of=/tmp/test_upload bs=1M count=10 2>/dev/null
sqscp /tmp/test_upload $SERVER_A:/tmp/
sqssh $SERVER_A "md5sum /tmp/test_upload"
md5sum /tmp/test_upload
# Checksums should match
```

### 5.2 Download single file
```
sqscp $SERVER_A:/tmp/test_upload /tmp/test_download
md5sum /tmp/test_upload /tmp/test_download
# Checksums should match
```

### 5.3 Upload to home directory (~)
```
sqscp /tmp/test_upload $SERVER_A:~
sqssh $SERVER_A "ls -la ~/test_upload"
# File should exist in home directory
```

### 5.4 Upload to current directory (.)
```
sqscp /tmp/test_upload $SERVER_A:.
```

### 5.5 Download with ~ path
```
sqscp $SERVER_A:~/test_upload /tmp/test_from_home
md5sum /tmp/test_upload /tmp/test_from_home
```

### 5.6 Multiple source files
```
echo "a" > /tmp/multi_a.txt
echo "b" > /tmp/multi_b.txt
sqscp /tmp/multi_a.txt /tmp/multi_b.txt $SERVER_A:/tmp/
sqssh $SERVER_A "cat /tmp/multi_a.txt /tmp/multi_b.txt"
```

### 5.7 Recursive upload
```
mkdir -p /tmp/test_dir/sub
echo "file1" > /tmp/test_dir/a.txt
echo "file2" > /tmp/test_dir/sub/b.txt
sqscp -r /tmp/test_dir $SERVER_A:/tmp/
sqssh $SERVER_A "find /tmp/test_dir -type f | sort"
# Should show a.txt and sub/b.txt
```

### 5.8 Recursive download
```
sqscp -r $SERVER_A:/tmp/test_dir /tmp/test_dir_downloaded
diff -r /tmp/test_dir /tmp/test_dir_downloaded/test_dir
# Should show no differences
```

### 5.9 Preserve timestamps (-p)
```
sqscp -p /tmp/test_upload $SERVER_A:/tmp/test_preserved
sqssh $SERVER_A "stat /tmp/test_preserved"
stat /tmp/test_upload
# Modification times should match
```

### 5.10 Custom port (-P)
```
sqscp -P 4022 /tmp/test_upload $SERVER_A:/tmp/
```

### 5.11 Parallel directory transfers (varying -j)
```
sqscp -j 1 -r /tmp/test_dir $SERVER_A:/tmp/test_j1
sqscp -j 4 -r /tmp/test_dir $SERVER_A:/tmp/test_j4
sqscp -j 16 -r /tmp/test_dir $SERVER_A:/tmp/test_j16
sqscp -j 32 -r /tmp/test_dir $SERVER_A:/tmp/test_j32
```

### 5.12 Chunked parallel single-file upload (j > 1 on single file)
```
dd if=/dev/urandom of=/tmp/test_100mb bs=1M count=100 2>/dev/null
sqscp -j 8 /tmp/test_100mb $SERVER_A:/tmp/test_chunked
sqssh $SERVER_A "md5sum /tmp/test_chunked"
md5sum /tmp/test_100mb
# Checksums should match
```

### 5.13 Bandwidth limit (-l)
```
time sqscp -l 500 /tmp/test_upload $SERVER_A:/tmp/
# 10MB at 500KB/s should take ~20 seconds
```

### 5.14 Quiet mode (-q)
```
sqscp -q /tmp/test_upload $SERVER_A:/tmp/
# Should show no per-file progress output
```

### 5.15 Verbose mode (-v)
```
sqscp -v /tmp/test_upload $SERVER_A:/tmp/
# Should show debug logging
```

### 5.16 Permissions preserved
```
chmod 755 /tmp/test_upload
sqscp /tmp/test_upload $SERVER_A:/tmp/test_perms
sqssh $SERVER_A "stat -c %a /tmp/test_perms"
# Should show 755
```

### 5.17 Large file (1GB)
```
dd if=/dev/urandom of=/tmp/test_1gb bs=1M count=1024 2>/dev/null
sqscp /tmp/test_1gb $SERVER_A:/tmp/
sqssh $SERVER_A "md5sum /tmp/test_1gb"
md5sum /tmp/test_1gb
# Checksums should match
```

### 5.18 Directory without -r (error)
```
sqscp /tmp/test_dir $SERVER_A:/tmp/
# Should show "is a directory (use -r)"
```

---

## 6. Interactive File Transfer (sqsftp)

### 6.1 Connect and navigate
```
sqsftp $SERVER_A
sftp> pwd
sftp> ls
sftp> cd /tmp
sftp> pwd        # Should show /tmp
```

### 6.2 Help command
```
sftp> help
# Should list all available commands
sftp> ?
# Should also show help (if supported), otherwise "unknown command"
```

### 6.3 File information
```
sftp> stat /etc/motd
# Should show path, type, size, mode, modified time
```

### 6.4 Create and remove directory
```
sftp> mkdir /tmp/sftp_test_dir
sftp> ls /tmp/sftp_test_dir
sftp> rm /tmp/sftp_test_dir
```

### 6.5 Upload file (default remote name)
```
sftp> lcd /tmp
sftp> put test_upload
# Should upload to remote cwd with same filename
```

### 6.6 Upload file (custom remote name)
```
sftp> put test_upload custom_name.bin
```

### 6.7 Download file (default local name)
```
sftp> get test_upload
# Should download to local cwd with same filename
```

### 6.8 Download file (custom local path)
```
sftp> get test_upload /tmp/sftp_custom_download
```

### 6.9 Rename file
```
sftp> put test_upload rename_test
sftp> rename rename_test renamed_file
sftp> stat renamed_file
sftp> rm renamed_file
```

### 6.10 Paths with ~ expansion
```
sftp> cd ~
sftp> pwd        # Should show home directory
sftp> ls ~/
```

### 6.11 Local commands
```
sftp> lpwd
sftp> lcd /tmp
sftp> lpwd       # Should show /tmp
sftp> lls
```

### 6.12 Exit aliases
```
# Each of these should close the session:
sftp> quit
sftp> exit
sftp> bye
```

### 6.13 Unknown command
```
sftp> foobar
# Should show "unknown command: foobar (type 'help' for commands)"
```

### 6.14 Custom port
```
sqsftp -p 4022 $SERVER_A
```

### 6.15 Custom identity
```
sqsftp -i /tmp/test_key $SERVER_A
```

---

## 7. Key Agent (sqssh-agent + sqssh-add)

### 7.1 Start agent
```
eval $(sqssh-agent)
echo $SQSSH_AGENT_SOCK
# Should show ~/.sqssh/agent.sock path
```

### 7.2 Start agent in debug/foreground mode
```
sqssh-agent -d &
# Should run in foreground with debug output
kill %1
```

### 7.3 Custom socket path
```
sqssh-agent -s /tmp/test_agent.sock &
# Should create socket at specified path
kill %1
rm /tmp/test_agent.sock
```

### 7.4 Stale socket detection
```
# With agent already running:
sqssh-agent
# Should error: socket already exists / agent already running
```

### 7.5 List keys (empty)
```
sqssh-add -l
# Should show no keys or "agent has no keys"
```

### 7.6 Add default key
```
sqssh-add
# Should prompt for passphrase if key is encrypted
sqssh-add -l
# Should show the key with fingerprint and comment
```

### 7.7 Add specific key
```
sqssh-add /tmp/test_key
sqssh-add -l
# Should show both keys
```

### 7.8 Connect using agent (no passphrase prompt)
```
sqssh $SERVER_A
# Should connect without prompting for passphrase
exit
```

### 7.9 Remove specific key
```
sqssh-add -d /tmp/test_key
sqssh-add -l
# Should show only default key
```

### 7.10 Remove all keys
```
sqssh-add -D
sqssh-add -l
# Should show no keys
```

### 7.11 Agent socket permissions
```
ls -la ~/.sqssh/agent.sock
# Should show srw------- (mode 0600, owner only)
```

### 7.12 Agent socket is not a symlink
```
# Agent should refuse to use a symlink as socket path
ln -sf /tmp/evil ~/.sqssh/agent.sock
sqssh-agent
# Should detect symlink and refuse
rm ~/.sqssh/agent.sock
```

---

## 8. Server Control (sqsshctl)

### 8.1 Reload keys for current user
```
ssh $SERVER_A "sqsshctl reload-keys"
# Should succeed with confirmation message
```

### 8.2 Reload all keys (root only)
```
ssh $SERVER_A "sqsshctl reload-keys --all"
# Should succeed if running as root
```

### 8.3 Non-root user reload (own keys only)
```
ssh $SERVER_A "su - testuser -c 'sqsshctl reload-keys'"
# Should reload only testuser's authorized_keys
```

### 8.4 Non-root user reload --all (denied)
```
ssh $SERVER_A "su - testuser -c 'sqsshctl reload-keys --all'"
# Should fail with permission error
```

### 8.5 Custom socket path
```
ssh $SERVER_A "sqsshctl -s /var/run/sqssh/control.sock reload-keys"
```

---

## 9. Server Features (sqsshd)

### 9.1 Show public key
```
ssh $SERVER_A "sqsshd --show-pubkey"
# Should print base58 public key and exit
```

### 9.2 Graceful shutdown (SIGTERM)
```
# While connected via sqssh:
ssh $SERVER_A "systemctl stop sqsshd"
# Client should see "Connection closed by remote host." and exit cleanly
```

### 9.3 Zero-downtime restart (SIGUSR1)
```
# Connect a session:
sqssh $SERVER_A
tail -f /var/log/sqsshd.log

# In another terminal:
ssh $SERVER_A "systemctl reload sqsshd"

# Client should show "Server restarting. Reconnecting..."
# Then reconnect and resume the tail
```

### 9.4 Session persistence across restart
```
# Connect and start a long-running process
sqssh $SERVER_A
tail -f /var/log/sqsshd.log

# Trigger SIGUSR1 restart
# Session should reconnect, tail should continue outputting
# No MOTD or last login on reconnect
```

### 9.5 Connection migration
```
sqssh $SERVER_A
# Switch networks (WiFi ↔ Ethernet, toggle VPN)
# Session should continue without interruption
# Server logs should show "client migrated from X to Y"
```

### 9.6 Disable connection migration
```
ssh $SERVER_A "sqsshd --no-migration --show-pubkey"
# Or set ConnectionMigration no in config
```

### 9.7 MaxSessions enforcement
```
# Set MaxSessions 2 in /etc/sqssh/sqsshd.conf, restart
# Open 2 sessions — both should succeed
# Open 3rd session — should be rejected
```

### 9.8 MaxAuthTries enforcement
```
# Set MaxAuthTries 2 in config
# Attempt auth with wrong key multiple times
# Should disconnect after max attempts
```

### 9.9 AllowUsers
```
# Set AllowUsers root in config, restart
# Connect as root — should succeed
# Connect as other user — should fail with auth error
```

### 9.10 DenyUsers
```
# Set DenyUsers baduser in config, restart
# Connect as baduser — should fail
# Connect as root — should succeed
```

### 9.11 Auth mode: whitelist+user (default)
```
# Client key not in authorized_keys
sqssh-keygen -f /tmp/unknown_key
sqssh -i /tmp/unknown_key $SERVER_A
# Should timeout (whitelist drops unknown keys silently)
```

### 9.12 Auth mode: open+user
```
# Set AuthMode open+user in config, restart
# Any client can reach server, but needs key in authorized_keys to authenticate
```

### 9.13 Auth mode: whitelist-only
```
# Set AuthMode whitelist-only in config, restart
# Key in whitelist is sufficient, no authorized_keys check needed
```

### 9.14 Banner display
```
# Set Banner /etc/sqssh/banner in config
# Create banner file: echo "Welcome" > /etc/sqssh/banner
# Connect — should see "Welcome" before shell prompt
```

### 9.15 MOTD and last login
```
sqssh $SERVER_A
# First line should show "Last login: <date> from <host>"
# Then /etc/motd content
```

### 9.16 Hushlogin
```
sqssh $SERVER_A "touch ~/.hushlogin"
# Reconnect:
sqssh $SERVER_A
# Should NOT show last login or MOTD
sqssh $SERVER_A "rm ~/.hushlogin"
```

### 9.17 Hushlogin symlink (should not follow)
```
ssh $SERVER_A "ln -sf /etc/passwd ~/.hushlogin"
sqssh $SERVER_A
# Should still show MOTD (symlink not treated as file)
ssh $SERVER_A "rm ~/.hushlogin"
```

### 9.18 Multiple simultaneous connections
```
# Open 3 independent sqssh sessions to the same server
# All should work independently
# Each should show in server logs as separate connections
```

### 9.19 Config file override (-c)
```
ssh $SERVER_A "sqsshd -c /etc/sqssh/custom.conf --show-pubkey"
```

### 9.20 Log to file
```
ssh $SERVER_A "sqsshd --log-file /var/log/sqsshd-test.log --show-pubkey"
# Log file should be created
```

### 9.21 JSON logging
```
ssh $SERVER_A "sqsshd --log-json --show-pubkey"
```

### 9.22 Custom listen address
```
ssh $SERVER_A "sqsshd -l 127.0.0.1 -p 4022 --show-pubkey"
```

---

## 10. Configuration

### 10.1 Client config host aliases
```
# Add to ~/.sqssh/config:
# Host myserver
#     Hostname <ip>
#     User root
#     Port 22
sqssh myserver
# Should connect using config values
```

### 10.2 Client config identity file
```
# Host myserver
#     IdentityFile ~/.sqssh/work_key
sqssh myserver
# Should use the specified key
```

### 10.3 Client config host key
```
# Host myserver
#     HostKey <base58-pubkey>
# Should use this key instead of known_hosts lookup
```

### 10.4 Client config keepalive
```
# Host *
#     KeepAliveInterval 15
# Connection should stay alive over idle periods
```

### 10.5 Client config connect timeout
```
# Host *
#     ConnectTimeout 5
time sqssh user@192.0.2.1
# Should timeout in ~5 seconds
```

### 10.6 Client config connection migration
```
# Host *
#     ConnectionMigration yes
```

### 10.7 Client config wildcard matching
```
# Host *.prod
#     User deploy
#     Port 22
sqssh web1.prod    # Should use User deploy
```

### 10.8 Server config file
```
ssh $SERVER_A "cat /etc/sqssh/sqsshd.conf"
# Should show valid config with directives:
# ListenAddress, Port, HostKey, AuthMode, AuthorizedKeysFile,
# MaxSessions, MaxAuthTries, ControlSocket, ConnectionMigration,
# AllowUsers, DenyUsers, PrintMotd, PrintLastLog, Banner
```

---

## 11. File and Socket Permissions

### 11.1 Private key permissions
```
stat -f "%Lp" ~/.sqssh/id_ed25519
# Should be 600 (rw-------)
```

### 11.2 Public key permissions
```
stat -f "%Lp" ~/.sqssh/id_ed25519.pub
# Should be 644 (rw-r--r--)
```

### 11.3 ~/.sqssh directory permissions
```
stat -f "%Lp" ~/.sqssh
# Should be 700 (rwx------)
```

### 11.4 Agent socket permissions
```
stat -f "%Lp" ~/.sqssh/agent.sock
# Should be 600 (rw-------)
```

### 11.5 Control socket permissions
```
ssh $SERVER_A "stat -c %a /var/run/sqssh/control.sock"
# Should be 666 (rw-rw-rw-, any user can reload their own keys)
```

### 11.6 Server host key permissions
```
ssh $SERVER_A "stat -c %a /etc/sqssh/host_key"
# Should be 600 (rw-------)
```

### 11.7 Remote authorized_keys permissions
```
ssh $SERVER_A "stat -c %a ~/.sqssh/authorized_keys"
# Should be 600 (rw-------)
```

### 11.8 Remote ~/.sqssh directory permissions
```
ssh $SERVER_A "stat -c %a ~/.sqssh"
# Should be 700 (rwx------)
```

### 11.9 Authorized keys security checks
```
# Server rejects symlinked authorized_keys
ssh $SERVER_A "mv ~/.sqssh/authorized_keys ~/.sqssh/ak_backup && ln -s /tmp/evil ~/.sqssh/authorized_keys"
# Reload — should reject with error about symlink
ssh $SERVER_A "rm ~/.sqssh/authorized_keys && mv ~/.sqssh/ak_backup ~/.sqssh/authorized_keys"

# Server rejects world-writable authorized_keys
ssh $SERVER_A "chmod 666 ~/.sqssh/authorized_keys"
# Reload — should reject
ssh $SERVER_A "chmod 600 ~/.sqssh/authorized_keys"

# Server rejects files not owned by user or root
# (test with appropriate user setup)
```

### 11.10 Uploaded file ownership
```
sqscp /tmp/test_upload $SERVER_A:/tmp/test_ownership
ssh $SERVER_A "stat -c '%U:%G' /tmp/test_ownership"
# Should be owned by the authenticated user
```

### 11.11 Known hosts file
```
ls -la ~/.sqssh/known_hosts
# Should exist and be readable
```

### 11.12 Key map file
```
ls -la ~/.sqssh/key_map
# Created automatically on successful connect
# Should be readable by owner
```

---

## 12. Performance (sqscp benchmarks)

### 12.1 Single file benchmarks
```
# Create test files
dd if=/dev/urandom of=/tmp/bench_1kb bs=1024 count=1 2>/dev/null
dd if=/dev/urandom of=/tmp/bench_10mb bs=1M count=10 2>/dev/null
dd if=/dev/urandom of=/tmp/bench_100mb bs=1M count=100 2>/dev/null
dd if=/dev/urandom of=/tmp/bench_1gb bs=1M count=1024 2>/dev/null

# sqscp (server A → server B)
ssh $SERVER_A "sqscp /tmp/bench_1kb $SERVER_B:/tmp/"
ssh $SERVER_A "sqscp /tmp/bench_10mb $SERVER_B:/tmp/"
ssh $SERVER_A "sqscp /tmp/bench_100mb $SERVER_B:/tmp/"
ssh $SERVER_A "sqscp /tmp/bench_1gb $SERVER_B:/tmp/"

# scp baseline
ssh $SERVER_A "time scp -q /tmp/bench_1gb $SERVER_B:/tmp/scp_1gb"
```

### 12.2 Parallel transfer scaling (-j)
```
ssh $SERVER_A "sqscp -j 1 /tmp/bench_100mb $SERVER_B:/tmp/"
ssh $SERVER_A "sqscp -j 4 /tmp/bench_100mb $SERVER_B:/tmp/"
ssh $SERVER_A "sqscp -j 16 /tmp/bench_100mb $SERVER_B:/tmp/"
ssh $SERVER_A "sqscp -j 32 /tmp/bench_100mb $SERVER_B:/tmp/"
```

### 12.3 Many small files
```
# Create 1000 x 1KB files on server A
ssh $SERVER_A 'mkdir -p /tmp/bench_small && for i in $(seq 1 1000); do dd if=/dev/urandom of=/tmp/bench_small/f$i bs=1024 count=1 2>/dev/null; done'

ssh $SERVER_A "sqscp -r /tmp/bench_small $SERVER_B:/tmp/"
ssh $SERVER_A "time scp -qr /tmp/bench_small $SERVER_B:/tmp/bench_small_scp"
# sqscp should be 20x+ faster on many small files
```

### 12.4 Many small files with varying -j
```
ssh $SERVER_A "sqscp -j 1 -r /tmp/bench_small $SERVER_B:/tmp/j1"
ssh $SERVER_A "sqscp -j 4 -r /tmp/bench_small $SERVER_B:/tmp/j4"
ssh $SERVER_A "sqscp -j 16 -r /tmp/bench_small $SERVER_B:/tmp/j16"
ssh $SERVER_A "sqscp -j 32 -r /tmp/bench_small $SERVER_B:/tmp/j32"
```

### 12.5 Upload vs download comparison
```
# Upload
sqscp /tmp/bench_100mb $SERVER_A:/tmp/
# Download
sqscp $SERVER_A:/tmp/bench_100mb /tmp/bench_dl
# Compare rates
```

### 12.6 Verify transfer integrity
```
# After any benchmark, verify checksums match
ssh $SERVER_A "md5sum /tmp/bench_100mb"
ssh $SERVER_B "md5sum /tmp/bench_100mb"
# Should be identical
```

---

## 13. Error Handling

### 13.1 Connection error message
```
sqssh user@192.0.2.1
# Should show clear error with hints (check host, port, firewall, key)
# Should timeout in ~3 seconds
```

### 13.2 File not found (sqscp download)
```
sqscp $SERVER_A:/nonexistent/file /tmp/
# Should show error
```

### 13.3 Permission denied (sqscp upload)
```
sqscp /tmp/test_upload $SERVER_A:/root/readonly_dir/
# Should show permission error
```

### 13.4 Directory without -r
```
sqscp /tmp/test_dir $SERVER_A:/tmp/
# Should show "is a directory (use -r)"
```

### 13.5 Wrong passphrase
```
sqssh -i ~/.sqssh/id_ed25519 $SERVER_A
# Enter wrong passphrase
# Should show "decryption failed (wrong passphrase?)"
```

### 13.6 Agent not running
```
unset SQSSH_AGENT_SOCK
sqssh-add -l
# Should show error about agent connection
```

### 13.7 Server not running
```
sqssh $SERVER_A    # with sqsshd stopped
# Should timeout with connection error
```

---

## Cleanup

```
rm -f /tmp/test_key /tmp/test_key.pub /tmp/test_key_enc /tmp/test_key_enc.pub
rm -f /tmp/test_key_comment /tmp/test_key_comment.pub
rm -f /tmp/test_upload /tmp/test_download /tmp/sftp_downloaded
rm -f /tmp/test_100mb /tmp/test_1gb /tmp/test_from_home
rm -f /tmp/multi_a.txt /tmp/multi_b.txt /tmp/sftp_custom_download
rm -rf /tmp/test_dir /tmp/test_dir_downloaded
rm -f /tmp/unknown_key /tmp/unknown_key.pub
rm -f /tmp/bench_1kb /tmp/bench_10mb /tmp/bench_100mb /tmp/bench_1gb /tmp/bench_dl
```
