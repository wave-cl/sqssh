# sqssh Test Plan

Comprehensive manual test plan covering every feature of the sqssh suite. Requires two servers with sqsshd running and a client machine with all binaries installed.

## Prerequisites

```
# Server A: sqsshd running, accessible via SSH for setup
SERVER_A=user@server-a

# Server B: sqsshd running (used for server-to-server tests)
SERVER_B=user@server-b

# Verify binaries are installed
sqssh --help
sqscp --help
sqsftp --help
sqssh-keygen --help
sqssh-agent --help
sqssh-add --help
sqssh-copy-id --help
sqssh-keyscan --help
sqsshctl --help
```

---

## 1. Key Generation (sqssh-keygen)

### 1.1 Generate unencrypted keypair
```
sqssh-keygen -f /tmp/test_key
# Expected: Creates /tmp/test_key and /tmp/test_key.pub
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
cat /tmp/test_key_enc    # Should show: SQSSH-ED25519-PRIVATE-KEY (unencrypted)
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
```

---

## 2. Known Hosts Management (sqssh-keyscan)

### 2.1 Add a host
```
# Get server pubkey
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

### 4.9 Escape sequences
```
sqssh $SERVER_A
# Press Enter, then ~?
# Should show escape sequence help
# Press Enter, then ~.
# Should disconnect immediately
```

### 4.10 Custom port
```
sqssh -p 4022 $SERVER_A
```

### 4.11 Verbose mode
```
sqssh -v $SERVER_A
# Should show debug logging
exit
```

### 4.12 Connection timeout (unreachable host)
```
time sqssh user@192.0.2.1
# Should timeout in ~3 seconds with clear error message
```

### 4.13 Unknown host rejection
```
sqssh user@unknown.example.com
# Should fail with "no server key" error
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

### 5.3 Upload to home directory
```
sqscp /tmp/test_upload $SERVER_A:~
sqssh $SERVER_A "ls -la ~/test_upload"
```

### 5.4 Recursive upload
```
mkdir -p /tmp/test_dir/sub
echo "file1" > /tmp/test_dir/a.txt
echo "file2" > /tmp/test_dir/sub/b.txt
sqscp -r /tmp/test_dir $SERVER_A:/tmp/
sqssh $SERVER_A "find /tmp/test_dir -type f"
# Should show a.txt and sub/b.txt
```

### 5.5 Recursive download
```
sqscp -r $SERVER_A:/tmp/test_dir /tmp/test_dir_downloaded
diff -r /tmp/test_dir /tmp/test_dir_downloaded/test_dir
# Should show no differences
```

### 5.6 Preserve timestamps
```
sqscp -p /tmp/test_upload $SERVER_A:/tmp/test_preserved
sqssh $SERVER_A "stat /tmp/test_preserved"
stat /tmp/test_upload
# Modification times should match
```

### 5.7 Parallel transfers
```
sqscp -j 16 -r /tmp/test_dir $SERVER_A:/tmp/test_parallel
```

### 5.8 Bandwidth limit
```
time sqscp -l 500 /tmp/test_upload $SERVER_A:/tmp/
# 10MB at 500KB/s should take ~20 seconds
```

### 5.9 Quiet mode
```
sqscp -q /tmp/test_upload $SERVER_A:/tmp/
# Should show no progress output
```

### 5.10 Permissions preserved
```
chmod 755 /tmp/test_upload
sqscp /tmp/test_upload $SERVER_A:/tmp/test_perms
sqssh $SERVER_A "stat -c %a /tmp/test_perms"
# Should show 755
```

### 5.11 Large file (1GB)
```
dd if=/dev/urandom of=/tmp/test_1gb bs=1M count=1024 2>/dev/null
sqscp /tmp/test_1gb $SERVER_A:/tmp/
sqssh $SERVER_A "md5sum /tmp/test_1gb"
md5sum /tmp/test_1gb
# Checksums should match
```

### 5.12 Upload with ~ path
```
sqscp /tmp/test_upload $SERVER_A:~/test_tilde
sqssh $SERVER_A "ls ~/test_tilde"
```

---

## 6. Interactive File Transfer (sqsftp)

### 6.1 Connect and navigate
```
sqsftp $SERVER_A
sftp> pwd
sftp> ls
sftp> cd /tmp
sftp> pwd
# Should show /tmp
```

### 6.2 File information
```
sftp> stat /etc/motd
# Should show path, type, size, mode, modified time
```

### 6.3 Create and remove directory
```
sftp> mkdir /tmp/sftp_test_dir
sftp> ls /tmp/sftp_test_dir
sftp> rm /tmp/sftp_test_dir
```

### 6.4 Upload file
```
sftp> lcd /tmp
sftp> put test_upload
# Should show bytes transferred
```

### 6.5 Download file
```
sftp> get test_upload /tmp/sftp_downloaded
sftp> quit
md5sum /tmp/test_upload /tmp/sftp_downloaded
# Checksums should match
```

### 6.6 Rename file
```
sftp> put test_upload remote_rename_test
sftp> rename remote_rename_test remote_renamed
sftp> stat remote_renamed
sftp> rm remote_renamed
```

### 6.7 Local commands
```
sftp> lpwd
sftp> lcd /tmp
sftp> lls
```

---

## 7. Key Agent (sqssh-agent + sqssh-add)

### 7.1 Start agent
```
eval $(sqssh-agent)
echo $SQSSH_AGENT_SOCK
# Should show ~/.sqssh/agent.sock
```

### 7.2 List keys (empty)
```
sqssh-add -l
# Should show no keys
```

### 7.3 Add default key
```
sqssh-add
# Should prompt for passphrase if key is encrypted
sqssh-add -l
# Should show the key
```

### 7.4 Add specific key
```
sqssh-add /tmp/test_key
sqssh-add -l
# Should show both keys
```

### 7.5 Connect using agent
```
sqssh $SERVER_A
# Should connect without prompting for passphrase
exit
```

### 7.6 Remove specific key
```
sqssh-add -d /tmp/test_key
sqssh-add -l
# Should show only default key
```

### 7.7 Remove all keys
```
sqssh-add -D
sqssh-add -l
# Should show no keys
```

### 7.8 Agent socket permissions
```
ls -la ~/.sqssh/agent.sock
# Should show srw------- (0600)
```

---

## 8. Server Control (sqsshctl)

### 8.1 Reload keys for current user
```
ssh $SERVER_A "sqsshctl reload-keys"
# Should succeed
```

### 8.2 Reload all keys (root)
```
ssh $SERVER_A "sqsshctl reload-keys --all"
# Should succeed (if root)
```

---

## 9. Server Features (sqsshd)

### 9.1 Show public key
```
ssh $SERVER_A "sqsshd --show-pubkey"
# Should print base58 public key
```

### 9.2 Graceful shutdown
```
ssh $SERVER_A "systemctl stop sqsshd"
# Connected clients should see "Connection closed by remote host."
# and exit cleanly
```

### 9.3 Zero-downtime restart
```
# Connect a session
sqssh $SERVER_A
tail -f /var/log/syslog &

# In another terminal, trigger restart
ssh $SERVER_A "systemctl reload sqsshd"

# First terminal should show:
# "Server restarting. Reconnecting..."
# Then reconnect and resume the tail
```

### 9.4 Session persistence across restart
```
# Connect and start a long-running process
sqssh $SERVER_A
tail -f /var/log/sqsshd.log

# Trigger restart (SIGUSR1)
# Session should reconnect, tail should continue
```

### 9.5 Connection migration
```
# Connect from one network
sqssh $SERVER_A

# Switch networks (e.g., WiFi to Ethernet, or toggle VPN)
# Session should continue without interruption
# Server logs should show "client migrated"
```

### 9.6 MaxSessions enforcement
```
# Set MaxSessions 2 in server config
# Open 2 sessions — both should succeed
# Open 3rd session — should be rejected
```

### 9.7 AllowUsers / DenyUsers
```
# Set AllowUsers root in server config
# Connect as root — should succeed
# Connect as other user — should fail
```

### 9.8 Auth mode: whitelist+user (default)
```
# Client key not in authorized_keys — should timeout (whitelist rejects)
```

### 9.9 Auth mode: open+user
```
# Set AuthMode open+user
# Any client can reach server, but needs key in authorized_keys
```

### 9.10 Banner display
```
# Set Banner /etc/sqssh/banner in server config
# Connect — should see banner content before shell
```

### 9.11 MOTD and last login
```
sqssh $SERVER_A
# Should show "Last login: ..." and /etc/motd content
```

### 9.12 Hushlogin
```
sqssh $SERVER_A "touch ~/.hushlogin"
sqssh $SERVER_A
# Should NOT show last login or MOTD
sqssh $SERVER_A "rm ~/.hushlogin"
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
# Add to ~/.sqssh/config:
# Host myserver
#     IdentityFile ~/.sqssh/work_key

sqssh myserver
# Should use the specified key
```

### 10.3 Client config keepalive
```
# Add to ~/.sqssh/config:
# Host *
#     KeepAliveInterval 15
```

### 10.4 Server config file
```
ssh $SERVER_A "cat /etc/sqssh/sqsshd.conf"
# Should show valid config directives
```

---

## 11. Security

### 11.1 Unknown client rejected (whitelist mode)
```
sqssh-keygen -f /tmp/unknown_key
sqssh -i /tmp/unknown_key $SERVER_A
# Should timeout — whitelist drops unknown keys silently
```

### 11.2 Known client, wrong user
```
# Key in whitelist but not in target user's authorized_keys
sqssh otheruser@$SERVER_A
# Should fail with "authentication failed"
```

### 11.3 Authorized keys file permissions
```
ssh $SERVER_A "ls -la ~/.sqssh/authorized_keys"
# Should be readable
```

### 11.4 Agent socket permissions
```
ls -la ~/.sqssh/agent.sock
# Should be 0600 (owner only)
```

### 11.5 Control socket permissions
```
ssh $SERVER_A "ls -la /var/run/sqssh/control.sock"
# Should be 0666 (any user can reload their own keys)
```

---

## 12. Performance (sqscp benchmarks)

### 12.1 Server-to-server benchmark
```
# On Server A, targeting Server B:
ssh $SERVER_A "sqscp /tmp/test_1gb $SERVER_B:/tmp/"
# Note transfer rate

ssh $SERVER_A "time scp -q /tmp/test_1gb $SERVER_B:/tmp/"
# Compare with scp
```

### 12.2 Many small files
```
# Create 1000 x 1KB files
ssh $SERVER_A "mkdir -p /tmp/bench_small && for i in \$(seq 1 1000); do dd if=/dev/urandom of=/tmp/bench_small/f\$i bs=1024 count=1 2>/dev/null; done"

ssh $SERVER_A "sqscp -r /tmp/bench_small $SERVER_B:/tmp/"
ssh $SERVER_A "time scp -qr /tmp/bench_small $SERVER_B:/tmp/bench_small_scp"
# sqscp should be 20x+ faster
```

---

## 13. Error Handling

### 13.1 Connection error message
```
sqssh user@192.0.2.1
# Should show clear error with hints (check host, port, firewall, key)
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

---

## Cleanup

```
rm -f /tmp/test_key /tmp/test_key.pub /tmp/test_key_enc /tmp/test_key_enc.pub
rm -f /tmp/test_key_comment /tmp/test_key_comment.pub
rm -f /tmp/test_upload /tmp/test_download /tmp/sftp_downloaded /tmp/test_1gb
rm -rf /tmp/test_dir /tmp/test_dir_downloaded
rm -f /tmp/unknown_key /tmp/unknown_key.pub
```
