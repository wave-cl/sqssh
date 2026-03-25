# sqssh Test Plan

Comprehensive test plan covering every feature and code path of the sqssh suite.

## Test Modes

Tests are split into **automated** (can run non-interactively with an unencrypted test key) and **manual** (require interactive terminal input, passphrase entry, or physical actions like resizing a window).

```
# Choose your mode:
#   automated  — run all automated tests only
#   manual     — run manual tests only (prompted one at a time)
#   both       — run automated first, then prompt for manual tests
```

## Running

```bash
./tests/run.sh                          # uses default server
./tests/run.sh root@your-server         # custom server
SERVER_A=root@host ./tests/run.sh       # via env var
```

Output streams in real-time with colored PASS/FAIL per test and section summaries. Stops on first failure.

## Reporting

When running manually (without the script), report results after each test section (A0, A1, A2, etc.) before proceeding to the next. If any test fails, **stop immediately** and report the failure — do not continue to subsequent sections until the failure is resolved.

## Prerequisites

```
# Server A: sqsshd running, accessible via SSH for setup
SERVER_A=root@167.235.197.87

# Server B: sqsshd running (used for server-to-server and benchmark tests)
SERVER_B=root@46.224.104.133
```

---

# Automated Tests

All tests below can run non-interactively using `-i /tmp/test_key`.

## A0. Setup (mandatory — gates all other tests)

This section generates the test key, deploys it, restarts sqsshd to ensure the
whitelist is fresh, and verifies end-to-end connectivity. If any step fails, all
subsequent tests should be skipped.

### A0.1 Verify binaries installed
```
MISSING=0
for bin in sqssh sqscp sqsftp sqssh-keygen sqssh-agent sqssh-add sqssh-copy-id sqssh-keyscan sqsshctl; do
  $bin --help > /dev/null 2>&1 && echo "$bin: OK" || { echo "$bin: MISSING"; MISSING=1; }
done
[ $MISSING -eq 0 ] || { echo "SETUP FAILED: missing binaries"; exit 1; }
```

### A0.2 Verify SSH and sqsshd are running on server
```
ssh -o ConnectTimeout=5 $SERVER_A "echo ssh-ok" || { echo "SETUP FAILED: cannot SSH to $SERVER_A (is sshd running?)"; exit 1; }
ssh $SERVER_A "systemctl is-active sqsshd" | grep -q active || { echo "SETUP FAILED: sqsshd not running on $SERVER_A"; exit 1; }
```

### A0.3 Generate unencrypted test key
```
rm -f /tmp/test_key /tmp/test_key.pub
echo "" | sqssh-keygen -f /tmp/test_key -C "automated-test"
[ -f /tmp/test_key ] && [ -f /tmp/test_key.pub ] || { echo "SETUP FAILED: key generation"; exit 1; }
```

### A0.4 Deploy test key to server
```
TESTPUB=$(awk '{print $2}' /tmp/test_key.pub)
ssh $SERVER_A "mkdir -p ~/.sqssh && chmod 700 ~/.sqssh"
ssh $SERVER_A "grep -qF '$TESTPUB' ~/.sqssh/authorized_keys 2>/dev/null || \
  (echo 'sqssh-ed25519 $TESTPUB automated-test' >> ~/.sqssh/authorized_keys && \
  chmod 600 ~/.sqssh/authorized_keys)"
```

### A0.5 Restart sqsshd to reload whitelist
```
ssh $SERVER_A "systemctl restart sqsshd"
sleep 2
ssh $SERVER_A "systemctl is-active sqsshd" | grep -q active || { echo "SETUP FAILED: sqsshd not active"; exit 1; }
```

### A0.6 Verify sqssh connectivity with test key
```
sqssh -i /tmp/test_key $SERVER_A "echo setup-ok" | grep -q "setup-ok" || { echo "SETUP FAILED: sqssh connection"; exit 1; }
echo "A0 SETUP COMPLETE"
```

---

## A1. Key Generation (sqssh-keygen)

### A1.1 Generate unencrypted keypair
```
echo "" | sqssh-keygen -f /tmp/test_key_a -C "test"
head -1 /tmp/test_key_a           # Expect: SQSSH-ED25519-PRIVATE-KEY
cat /tmp/test_key_a.pub           # Expect: sqssh-ed25519 <base58> test
```

### A1.2 Generate encrypted keypair
```
printf "pass\npass\n" | sqssh-keygen -f /tmp/test_key_enc -C "encrypted"
head -1 /tmp/test_key_enc         # Expect: SQSSH-ED25519-ENCRYPTED-KEY
```

### A1.3 Custom comment
```
echo "" | sqssh-keygen -f /tmp/test_key_c -C "work laptop"
grep "work laptop" /tmp/test_key_c.pub   # Should match
```

### A1.4 File permissions
```
stat -f "%Lp" /tmp/test_key_a       # Expect: 600
stat -f "%Lp" /tmp/test_key_a.pub   # Expect: 644
stat -f "%Lp" ~/.sqssh              # Expect: 700
```

---

## A2. Known Hosts Management (sqssh-keyscan)

### A2.1 Add, list, remove
```
PUBKEY=$(ssh $SERVER_A "sqsshd --show-pubkey")
sqssh-keyscan add test.example.com $PUBKEY
sqssh-keyscan list | grep test.example.com   # Should match
sqssh-keyscan remove test.example.com
sqssh-keyscan list | grep test.example.com   # Should NOT match
```

### A2.2 Wildcard patterns
```
sqssh-keyscan add "*.internal" $PUBKEY
sqssh-keyscan list | grep '*.internal'       # Should match
sqssh-keyscan remove "*.internal"
```

---

## A3. Remote Command Execution (sqssh)

### A3.1 Echo
```
sqssh -i /tmp/test_key $SERVER_A "echo hello"
# Expect: hello
# Exit code: 0
```

### A3.2 Exit code propagation
```
sqssh -i /tmp/test_key $SERVER_A "exit 42"
echo $?    # Expect: 42
```

### A3.3 Stderr and stdout
```
sqssh -i /tmp/test_key $SERVER_A "echo err >&2; echo out"
# Expect both "err" and "out" in output
```

### A3.4 Unknown host rejection
```
sqssh -i /tmp/test_key user@192.0.2.1
# Expect: "unknown host" error, immediate exit
```

### A3.5 Unknown host by name
```
sqssh -i /tmp/test_key user@unknown.example.com
# Expect: "unknown host" error
```

### A3.6 Multiple simultaneous connections
```
sqssh -i /tmp/test_key $SERVER_A "echo conn1" &
sqssh -i /tmp/test_key $SERVER_A "echo conn2" &
sqssh -i /tmp/test_key $SERVER_A "echo conn3" &
wait
# All three should print their output
```

---

## A4. File Copy (sqscp)

### A4.1 Upload single file with checksum verification
```
dd if=/dev/urandom of=/tmp/test_upload bs=1M count=10 2>/dev/null
sqscp -i /tmp/test_key /tmp/test_upload $SERVER_A:/tmp/test_upload_v
LOCAL=$(md5sum /tmp/test_upload | cut -d' ' -f1)      # or md5 -q on macOS
REMOTE=$(ssh $SERVER_A "md5sum /tmp/test_upload_v" | cut -d' ' -f1)
[ "$LOCAL" = "$REMOTE" ] && echo PASS || echo FAIL
```

### A4.2 Download single file
```
sqscp -i /tmp/test_key $SERVER_A:/tmp/test_upload_v /tmp/test_download
# Checksum should match A4.1
```

### A4.3 Upload to home directory (~)
```
sqscp -i /tmp/test_key /tmp/test_upload $SERVER_A:~
ssh $SERVER_A "test -f ~/test_upload" && echo PASS
```

### A4.4 Download with ~ path
```
sqscp -i /tmp/test_key $SERVER_A:~/test_upload /tmp/test_from_home
# Checksum should match
```

### A4.5 Multiple source files
```
echo "aaa" > /tmp/multi_a.txt
echo "bbb" > /tmp/multi_b.txt
sqscp -i /tmp/test_key /tmp/multi_a.txt /tmp/multi_b.txt $SERVER_A:/tmp/
ssh $SERVER_A "cat /tmp/multi_a.txt /tmp/multi_b.txt"
# Expect: aaa\nbbb
```

### A4.6 Recursive upload
```
mkdir -p /tmp/test_dir/sub
echo "file1" > /tmp/test_dir/a.txt
echo "file2" > /tmp/test_dir/sub/b.txt
sqscp -i /tmp/test_key -r /tmp/test_dir $SERVER_A:/tmp/
ssh $SERVER_A "find /tmp/test_dir -type f | sort"
# Expect: a.txt and sub/b.txt
```

### A4.7 Recursive download
```
sqscp -i /tmp/test_key -r $SERVER_A:/tmp/test_dir /tmp/test_dir_dl
diff -r /tmp/test_dir /tmp/test_dir_dl/test_dir
# Expect: no differences
```

### A4.8 Preserve timestamps (-p)
```
sqscp -i /tmp/test_key -p /tmp/test_upload $SERVER_A:/tmp/test_ts
# Local and remote mtime should match
```

### A4.9 Permissions preserved
```
chmod 755 /tmp/test_upload
sqscp -i /tmp/test_key /tmp/test_upload $SERVER_A:/tmp/test_pm
ssh $SERVER_A "stat -c %a /tmp/test_pm"
# Expect: 755
```

### A4.10 Directory without -r (error)
```
sqscp -i /tmp/test_key /tmp/test_dir $SERVER_A:/tmp/
# Expect: "is a directory (use -r)" error, non-zero exit
```

---

## A5. Server Control (sqsshctl)

### A5.1 Reload keys
```
ssh $SERVER_A "sqsshctl reload-keys"
# Expect: "reloaded keys for 'root'"
```

### A5.2 Reload all keys (root)
```
ssh $SERVER_A "sqsshctl reload-keys --all"
# Expect: "reloaded all keys (N total)"
```

---

## A6. Server Features (sqsshd) — automated subset

### A6.1 Show public key
```
ssh $SERVER_A "sqsshd --show-pubkey"
# Expect: base58 public key string
```

### A6.2 Graceful shutdown
```
sqssh -i /tmp/test_key $SERVER_A "sleep 30" &
PID=$!
sleep 2
ssh $SERVER_A "systemctl stop sqsshd"
sleep 8
kill -0 $PID 2>/dev/null && echo FAIL || echo PASS
# IMPORTANT: restart sqsshd immediately — remaining tests need it
ssh $SERVER_A "systemctl start sqsshd"
sleep 2
ssh $SERVER_A "systemctl is-active sqsshd" | grep -q active || { echo "CRITICAL: sqsshd failed to restart"; exit 1; }
```

### A6.3 Unknown key silently dropped
```
echo "" | sqssh-keygen -f /tmp/unknown_key -C "unknown"
timeout 5 sqssh -i /tmp/unknown_key $SERVER_A "echo should-not-reach" 2>&1
# Expect: timeout or connection error (key not in whitelist)
```

### A6.4 Hushlogin suppresses MOTD
```
ssh $SERVER_A "touch ~/.hushlogin"
sqssh -i /tmp/test_key $SERVER_A "echo after-hushlogin"
# Expect: no MOTD or last login message
ssh $SERVER_A "rm -f ~/.hushlogin"
```

### A6.5 Hushlogin symlink not followed
```
ssh $SERVER_A "ln -sf /etc/passwd ~/.hushlogin"
sqssh -i /tmp/test_key $SERVER_A "echo after-symlink"
# Expect: MOTD and last login SHOULD appear (symlink ignored)
ssh $SERVER_A "rm -f ~/.hushlogin"
```

### A6.6 Multiple simultaneous connections
```
sqssh -i /tmp/test_key $SERVER_A "echo c1" &
sqssh -i /tmp/test_key $SERVER_A "echo c2" &
sqssh -i /tmp/test_key $SERVER_A "echo c3" &
wait
# All three should succeed
```

---

## A7. Error Handling

### A7.1 Unknown host
```
sqssh -i /tmp/test_key user@192.0.2.1
# Expect: "unknown host" error
```

### A7.2 File not found (download)
```
sqscp -i /tmp/test_key $SERVER_A:/nonexistent/file /tmp/
# Expect: "No such file or directory" error
```

### A7.3 Directory without -r
```
sqscp -i /tmp/test_key /tmp/test_dir $SERVER_A:/tmp/
# Expect: "is a directory (use -r)" error
```

### A7.4 Wrong passphrase
```
echo "wrong" | sqssh $SERVER_A
# Expect: "decryption failed (wrong passphrase?)"
```

### A7.5 Agent not running
```
SQSSH_AGENT_SOCK=/tmp/nonexistent.sock sqssh-add -l
# Expect: connection error
```

---

## A8. SFTP (piped stdin)

### A8.1 Navigate
```
echo -e "pwd\ncd /tmp\npwd\nquit" | sqsftp -i /tmp/test_key $SERVER_A
# Expect: first pwd shows home dir, second shows /tmp
```

### A8.2 Upload and download
```
echo -e "lcd /tmp\nput test_upload\nget test_upload /tmp/sftp_dl\nquit" | sqsftp -i /tmp/test_key $SERVER_A
md5sum /tmp/test_upload /tmp/sftp_dl
# Checksums should match
```

### A8.3 Directory operations
```
echo -e "mkdir /tmp/sftp_auto_test\nls /tmp/sftp_auto_test\nrm /tmp/sftp_auto_test\nquit" | sqsftp -i /tmp/test_key $SERVER_A
```

### A8.4 File info and rename
```
echo -e "stat /etc/motd\nquit" | sqsftp -i /tmp/test_key $SERVER_A
# Expect: shows path, type, size, mode
```

### A8.5 Help and unknown command
```
echo -e "help\nfoobar\nquit" | sqsftp -i /tmp/test_key $SERVER_A
# Expect: help output, then "unknown command: foobar"
```

### A8.6 Local commands
```
echo -e "lpwd\nlcd /tmp\nlpwd\nquit" | sqsftp -i /tmp/test_key $SERVER_A
# Expect: second lpwd shows /tmp
```

### A8.7 Tilde expansion
```
echo -e "cd ~\npwd\nquit" | sqsftp -i /tmp/test_key $SERVER_A
# Expect: pwd shows home directory
```

---

## A9. Key Agent (unencrypted key operations)

### A9.1 Add and list unencrypted key
```
# Start agent, add unencrypted test key, verify
sqssh-agent &
AGENT_PID=$!
export SQSSH_AGENT_SOCK=~/.sqssh/agent.sock
sleep 1
sqssh-add /tmp/test_key
sqssh-add -l             # Should show the key
```

### A9.2 Remove specific key
```
sqssh-add -d /tmp/test_key
sqssh-add -l             # Should be empty
```

### A9.3 Remove all keys
```
sqssh-add /tmp/test_key
sqssh-add -D
sqssh-add -l             # Should be empty
kill $AGENT_PID
```

### A9.4 Stale socket detection
```
touch ~/.sqssh/agent.sock
sqssh-agent 2>&1
# Expect: error about existing socket
rm -f ~/.sqssh/agent.sock
```

---

## A10. Configuration (-F flag)

### A10.1 Host alias via -F
```
cat > /tmp/sqssh_test_config << EOF
Host testhost
    Hostname 167.235.197.87
    User root
    IdentityFile /tmp/test_key
EOF
sqssh -F /tmp/sqssh_test_config testhost "echo config-works"
# Expect: "config-works"
```

### A10.2 Wildcard matching via -F
```
cat > /tmp/sqssh_test_config << EOF
Host *.testdomain
    Hostname 167.235.197.87
    User root
    IdentityFile /tmp/test_key
EOF
sqssh -F /tmp/sqssh_test_config server1.testdomain "echo wildcard-works"
# Expect: "wildcard-works"
```

### A10.3 sqscp with -F
```
cat > /tmp/sqssh_test_config << EOF
Host testhost
    Hostname 167.235.197.87
    User root
    IdentityFile /tmp/test_key
EOF
sqscp -F /tmp/sqssh_test_config -i /tmp/test_key /tmp/test_upload root@testhost:/tmp/
# Expect: upload succeeds using config hostname resolution
```

### A10.4 sqsftp with -F
```
echo -e "pwd\nquit" | sqsftp -F /tmp/sqssh_test_config -i /tmp/test_key testhost
# Expect: shows home directory (config provides Hostname + User)
```

---

## A11. File and Socket Permissions

### A11.1 Client-side permissions
```
stat -f "%Lp" ~/.sqssh/id_ed25519       # Expect: 600
stat -f "%Lp" ~/.sqssh/id_ed25519.pub   # Expect: 644
stat -f "%Lp" ~/.sqssh                  # Expect: 700
stat -f "%Lp" ~/.sqssh/known_hosts      # Expect: 644
```

### A11.2 Server-side permissions
```
ssh $SERVER_A "stat -c %a /etc/sqssh/host_key"            # Expect: 600
ssh $SERVER_A "stat -c %a ~/.sqssh"                        # Expect: 700
ssh $SERVER_A "stat -c %a ~/.sqssh/authorized_keys"        # Expect: 600
ssh $SERVER_A "stat -c %a /run/sqssh/control.sock 2>/dev/null || \
               stat -c %a /var/run/sqssh/control.sock"     # Expect: 666
```

---

## A12. CLI Flag Compatibility

### A12.1 sqssh --version
```
sqssh --version
# Expect: "sqssh 0.1.0" (or current version)
```

### A12.2 sqssh -l login name
```
sqssh -i /tmp/test_key -l root 167.235.197.87 "whoami"
# Expect: root
```

### A12.3 sqssh -N no command (hold connection)
```
timeout 3 sqssh -i /tmp/test_key -N $SERVER_A 2>&1
# Expect: exits after timeout, no shell prompt
```

### A12.4 sqssh -n no stdin
```
echo "should not reach" | sqssh -i /tmp/test_key -n $SERVER_A "cat"
# Expect: cat exits immediately (stdin is /dev/null)
```

### A12.5 sqssh -q quiet mode
```
sqssh -i /tmp/test_key -q $SERVER_A "echo quiet-test" 2>&1
# Expect: only "quiet-test", no warnings or diagnostics
```

### A12.6 sqssh stub -L (local forward)
```
sqssh -i /tmp/test_key -L 8080:localhost:80 $SERVER_A 2>&1
echo $?
# Expect: "sqssh: local port forwarding (-L) is not yet implemented"
# Exit code: 1
```

### A12.7 sqssh stub -R (remote forward)
```
sqssh -i /tmp/test_key -R 8080:localhost:80 $SERVER_A 2>&1
echo $?
# Expect: "sqssh: remote port forwarding (-R) is not yet implemented"
# Exit code: 1
```

### A12.8 sqssh stub -D (dynamic forward)
```
sqssh -i /tmp/test_key -D 1080 $SERVER_A 2>&1
echo $?
# Expect: "sqssh: dynamic port forwarding (-D) is not yet implemented"
# Exit code: 1
```

### A12.9 sqssh stub -J (ProxyJump)
```
sqssh -i /tmp/test_key -J bastion $SERVER_A 2>&1
echo $?
# Expect: "sqssh: ProxyJump (-J) is not yet implemented"
# Exit code: 1
```

### A12.10 sqssh -o option (accepted, ignored)
```
sqssh -i /tmp/test_key -o StrictHostKeyChecking=no $SERVER_A "echo opt-test"
# Expect: "opt-test" (option accepted but ignored)
```

### A12.11 sqscp --version
```
sqscp --version
# Expect: "sqscp 0.1.0"
```

### A12.12 sqscp stub -J
```
sqscp -J bastion /tmp/test_upload $SERVER_A:/tmp/ 2>&1
echo $?
# Expect: "sqscp: ProxyJump (-J) is not yet implemented"
# Exit code: 1
```

### A12.13 sqscp -o (accepted, ignored)
```
sqscp -i /tmp/test_key -o Compression=yes /tmp/test_upload $SERVER_A:/tmp/test_opt
# Expect: upload succeeds
```

### A12.14 sqsftp --version
```
sqsftp --version
# Expect: "sqsftp 0.1.0"
```

### A12.15 sqsftp -P port (capital P alias)
```
echo "pwd\nquit" | sqsftp -i /tmp/test_key -P 22 $SERVER_A
# Expect: same as -p 22
```

### A12.16 sqsftp -b batch file
```
cat > /tmp/sftp_batch << EOF
pwd
cd /tmp
pwd
quit
EOF
sqsftp -i /tmp/test_key -b /tmp/sftp_batch $SERVER_A
# Expect: shows home dir, then /tmp, no sftp> prompt
rm /tmp/sftp_batch
```

### A12.17 sqsftp -q quiet mode
```
echo -e "pwd\nquit" | sqsftp -i /tmp/test_key -q $SERVER_A 2>&1
# Expect: output with no extra diagnostics
```

### A12.18 sqssh-keygen --version
```
sqssh-keygen --version
# Expect: "sqssh-keygen 0.1.0"
```

### A12.19 sqssh-keygen -l fingerprint (short flag)
```
sqssh-keygen -l /tmp/test_key
# Expect: same output as --fingerprint
```

### A12.20 sqssh-keygen -p change passphrase (short flag)
```
# Generate unencrypted key, then add passphrase
sqssh-keygen -f /tmp/test_key_pp -C "pp-test" -N ""
printf "new\nnew\n" | sqssh-keygen -p /tmp/test_key_pp
head -1 /tmp/test_key_pp
# Expect: SQSSH-ED25519-ENCRYPTED-KEY
# Now remove passphrase (enter old passphrase, then empty new passphrase)
printf "new\n\n\n" | sqssh-keygen -p /tmp/test_key_pp
head -1 /tmp/test_key_pp
# Expect: SQSSH-ED25519-PRIVATE-KEY (passphrase removed)
rm -f /tmp/test_key_pp /tmp/test_key_pp.pub
```

### A12.21 sqssh-keygen -N non-interactive passphrase
```
sqssh-keygen -f /tmp/test_key_ni -C "ni-test" -N ""
head -1 /tmp/test_key_ni
# Expect: SQSSH-ED25519-PRIVATE-KEY (no passphrase)
sqssh-keygen -f /tmp/test_key_ni2 -C "ni-test2" -N "secret"
head -1 /tmp/test_key_ni2
# Expect: SQSSH-ED25519-ENCRYPTED-KEY
rm -f /tmp/test_key_ni /tmp/test_key_ni.pub /tmp/test_key_ni2 /tmp/test_key_ni2.pub
```

### A12.22 sqssh-keygen -y print public key
```
sqssh-keygen -y -f /tmp/test_key
# Expect: sqssh-ed25519 <base58>
```

### A12.23 sqssh-keygen -q quiet mode
```
echo "" | sqssh-keygen -q -f /tmp/test_key_quiet -C "quiet"
# Expect: no "Generated" message, just creates files
rm -f /tmp/test_key_quiet /tmp/test_key_quiet.pub
```

### A12.24 sqssh-keygen -t type validation
```
sqssh-keygen -t ed25519 -f /tmp/test_key_t -N "" 2>&1
# Expect: generates key (ed25519 is valid)
sqssh-keygen -t rsa -f /tmp/test_key_rsa -N "" 2>&1
echo $?
# Expect: error about unsupported key type, exit 1
rm -f /tmp/test_key_t /tmp/test_key_t.pub
```

### A12.25 sqssh-keyscan scan subcommand
```
sqssh-keyscan scan 167.235.197.87 2>&1
# Expect: message about sQUIC silent servers, not an error
echo $?
# Expect: 0
```

### A12.26 sqssh-keyscan --version
```
sqssh-keyscan --version
# Expect: "sqssh-keyscan 0.1.0"
```

### A12.27 sqssh-agent -k kill
```
sqssh-agent &
AGENT_PID=$!
sleep 1
sqssh-agent -k
sleep 1
kill -0 $AGENT_PID 2>/dev/null && echo FAIL || echo PASS
rm -f ~/.sqssh/agent.sock
```

### A12.28 sqssh-agent --version
```
sqssh-agent --version
# Expect: "sqssh-agent 0.1.0"
```

### A12.29 sqssh-add -L list public keys
```
sqssh-agent &
AGENT_PID=$!
export SQSSH_AGENT_SOCK=~/.sqssh/agent.sock
sleep 1
sqssh-add /tmp/test_key
sqssh-add -L
# Expect: sqssh-ed25519 <base58> <comment>
sqssh-add -l
# Expect: fingerprint only
kill $AGENT_PID
rm -f ~/.sqssh/agent.sock
```

### A12.30 sqssh-add -q quiet mode
```
sqssh-agent &
AGENT_PID=$!
export SQSSH_AGENT_SOCK=~/.sqssh/agent.sock
sleep 1
sqssh-add -q /tmp/test_key 2>&1
# Expect: no "Identity added" message
kill $AGENT_PID
rm -f ~/.sqssh/agent.sock
```

### A12.31 sqssh-add stub -x/-X lock/unlock
```
sqssh-add -x 2>&1
# Expect: "not yet implemented"
sqssh-add -X 2>&1
# Expect: "not yet implemented"
```

### A12.32 sqssh-add --version
```
sqssh-add --version
# Expect: "sqssh-add 0.1.0"
```

### A12.33 sqssh-copy-id -n dry run
```
sqssh-copy-id -n -i /tmp/test_key.pub $SERVER_A 2>&1
# Expect: "Would deploy key: <pubkey> to <host>" without connecting
```

### A12.34 sqssh-copy-id --version
```
sqssh-copy-id --version
# Expect: "sqssh-copy-id 0.1.0"
```

### A12.35 sqsshctl --version
```
sqsshctl --version
# Expect: "sqsshctl 0.1.0"
```

---

## A13. Destructive Security Tests

> **Warning:** These tests temporarily modify authorized_keys on the server.
> They run last (after all other tests) to avoid breaking connectivity.

### A13.1 Authorized keys security: symlink rejected
```
ssh $SERVER_A "cp ~/.sqssh/authorized_keys ~/.sqssh/ak_backup"
ssh $SERVER_A "rm ~/.sqssh/authorized_keys && ln -s /tmp/evil ~/.sqssh/authorized_keys"
ssh $SERVER_A "sqsshctl reload-keys"
# Expect: error about symlink
ssh $SERVER_A "rm ~/.sqssh/authorized_keys && mv ~/.sqssh/ak_backup ~/.sqssh/authorized_keys"
```

### A13.2 Authorized keys security: world-writable rejected
```
ssh $SERVER_A "chmod 666 ~/.sqssh/authorized_keys"
ssh $SERVER_A "sqsshctl reload-keys"
# Expect: error about permissions
ssh $SERVER_A "chmod 600 ~/.sqssh/authorized_keys"
```

---

## A14. Cleanup (automated)
```
rm -f /tmp/test_key /tmp/test_key.pub /tmp/test_key_a /tmp/test_key_a.pub
rm -f /tmp/test_key_enc /tmp/test_key_enc.pub /tmp/test_key_c /tmp/test_key_c.pub
rm -f /tmp/test_upload /tmp/test_download /tmp/test_from_home /tmp/sftp_dl
rm -f /tmp/multi_a.txt /tmp/multi_b.txt
rm -rf /tmp/test_dir /tmp/test_dir_dl
rm -f /tmp/unknown_key /tmp/unknown_key.pub
rm -f /tmp/sqssh_test_config /tmp/sftp_batch
rm -f ~/.sqssh/config.bak
```

---

# Manual Tests

These tests require a real terminal (PTY rendering, escape sequences, window resize, passphrase entry, or physical network changes).

## M1. Interactive Shell

### M1.1 PTY — htop
```
sqssh -i /tmp/test_key $SERVER_A
htop
# Expect: htop renders correctly with colors and layout
# Press q to quit htop
exit
```

### M1.2 Ctrl+C handling
```
sqssh -i /tmp/test_key $SERVER_A
sleep 100
# Press Ctrl+C
# Expect: sleep interrupted, shell still alive (requires PTY mode)
exit
```

### M1.3 Window resize
```
sqssh -i /tmp/test_key $SERVER_A
# Resize terminal window by dragging
stty size
# Expect: output reflects new dimensions
exit
```

### M1.4 Escape: disconnect (~.)
```
sqssh -i /tmp/test_key $SERVER_A
# Press Enter, then type ~.
# Expect: immediate disconnect
```

### M1.5 Escape: help (~?)
```
sqssh -i /tmp/test_key $SERVER_A
# Press Enter, then type ~?
# Expect: escape sequence help listing
```

### M1.6 Escape: literal tilde (~~)
```
sqssh -i /tmp/test_key $SERVER_A
# Press Enter, then type ~~
# Expect: single ~ sent to remote shell
```

### M1.7 Passphrase-protected key
```
sqssh $SERVER_A
# Expect: passphrase prompt
# Enter correct passphrase
# Expect: connection succeeds
exit
```

---

## M2. Key Agent (passphrase operations)

### M2.1 Start agent and add encrypted key
```
eval $(sqssh-agent)
sqssh-add                             # Enter passphrase when prompted
sqssh-add -l                          # Expect: key listed
```

### M2.2 Connect via agent (no passphrase prompt)
```
sqssh $SERVER_A
# Expect: no passphrase prompt, direct connection
exit
```

---

## M3. Server Features — interactive

### M3.1 Zero-downtime restart (SIGUSR1)
```
# Terminal 1:
sqssh -i /tmp/test_key $SERVER_A
tail -f /var/log/sqsshd.log

# Terminal 2:
ssh $SERVER_A "systemctl reload sqsshd"

# Expect in Terminal 1:
#   "Server restarting. Reconnecting..."
#   Session reconnects, tail resumes
#   No MOTD or last login on reconnect
```

### M3.2 Session persistence across restart
```
# Same as M3.1 — verify tail process PID is the same before and after
```

### M3.3 Connection migration
```
sqssh -i /tmp/test_key $SERVER_A
# Switch networks (WiFi to Ethernet, toggle VPN, etc.)
# Expect: session continues without interruption
# Server logs should show "client migrated from X to Y"
```

### M3.4 MaxSessions enforcement
```
# Set MaxSessions 2 in /etc/sqssh/sqsshd.conf, restart sqsshd
# Open 2 sqssh sessions — both should succeed
# Open 3rd session — should be rejected
# Reset MaxSessions and restart
```

---

## Cleanup (manual)
```
rm -f /tmp/test_key /tmp/test_key.pub
rm -f /tmp/bench_1kb /tmp/bench_10mb /tmp/bench_100mb /tmp/bench_1gb /tmp/bench_dl
ssh $SERVER_A "rm -f /tmp/test_upload* /tmp/test_download /tmp/test_ts /tmp/test_pm /tmp/test_perms"
ssh $SERVER_A "rm -rf /tmp/test_dir /tmp/bench_*"
```
