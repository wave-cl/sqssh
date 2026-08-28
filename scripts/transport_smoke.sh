#!/bin/bash
# Transport smoke test: does an sqssh client still reach an sqsshd?
#
# Nothing else in this repository opens a connection. The unit tests parse
# config, round-trip keys and drive sqssh-keygen; all of them pass whether or
# not the two binaries can talk. That gap went unnoticed until squic v0.16.0,
# when this repository was moved across the SIP-3 flag day — a breaking change
# to the Initial envelope — and `cargo test` had nothing to say about it.
#
# Two cases, and the second is what makes the first mean anything:
#
#   1. AuthMode open+user, so squic admits any caller and sqsshd decides.
#      With no authorized_keys on this machine the client is refused *at the
#      application layer*, which it can only reach through a completed sQUIC
#      handshake. An auth failure is therefore a transport success.
#
#   2. AuthMode whitelist+user with nothing in the whitelist. sqsshd passes an
#      enabled-but-empty key set to squic, which SIP-8 says must block
#      everyone, and the server drops the Initial without answering. The client
#      fails at the transport instead, with a different error.
#
# If case 1 ever starts failing the way case 2 does, the wire has moved. If both
# cases pass with the same error, this test has stopped testing anything.
set -u
cd "$(dirname "$0")/.." || exit 2

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "building..."
cargo build -q --bin sqssh --bin sqsshd --bin sqssh-keygen || exit 2
BIN="$(cargo metadata --format-version 1 --no-deps -q 2>/dev/null \
  | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/debug"
[ -x "$BIN/sqsshd" ] || { echo "no sqsshd at $BIN"; exit 2; }

"$BIN/sqssh-keygen" -f "$WORK/host_key" -N "" -q >/dev/null 2>&1 || exit 2
"$BIN/sqssh-keygen" -f "$WORK/client_key" -N "" -q >/dev/null 2>&1 || exit 2

pass=0; fail=0

# $1 = case label  $2 = auth mode  $3 = expected marker  $4 = extra server config
run() {
  local port=$((30000 + RANDOM % 20000))
  cat > "$WORK/sqsshd.conf" <<CONF
ListenAddress 127.0.0.1
Port $port
AuthMode $2
${4:-}
CONF
  local pub
  pub=$("$BIN/sqsshd" -c "$WORK/sqsshd.conf" -k "$WORK/host_key" --show-pubkey 2>/dev/null | tail -1)
  if [ -z "$pub" ]; then
    echo "  [$1] FAIL: sqsshd would not report its public key"
    fail=$((fail+1)); return
  fi

  "$BIN/sqsshd" -c "$WORK/sqsshd.conf" -k "$WORK/host_key" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  # Wait for the socket rather than sleeping a guessed interval.
  local up=""
  for _ in $(seq 1 50); do
    grep -q "listening on" "$WORK/server.log" 2>/dev/null && { up=1; break; }
    sleep 0.1
  done
  if [ -z "$up" ]; then
    echo "  [$1] FAIL: sqsshd never came up"; sed 's/^/      /' "$WORK/server.log" | tail -3
    kill "$SERVER_PID" 2>/dev/null; SERVER_PID=""; fail=$((fail+1)); return
  fi

  # HostKey is pinned here so the client never reads or writes the developer's
  # ~/.sqssh/known_hosts.
  cat > "$WORK/client.conf" <<CONF
Host 127.0.0.1
    Port $port
    HostKey $pub
    IdentityFile $WORK/client_key
    ConnectTimeout 3
CONF

  "$BIN/sqssh" -F "$WORK/client.conf" "smoketest@127.0.0.1" true >"$WORK/client.out" 2>&1
  local rc=$?
  kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=""

  if grep -qi "$3" "$WORK/client.out"; then
    echo "  [$1] PASS  ($(grep -io "$3" "$WORK/client.out" | head -1))"
    pass=$((pass+1))
  else
    echo "  [$1] FAIL: expected '$3' in the client's output, got exit $rc:"
    sed 's/^/      /' "$WORK/client.out" | head -8
    fail=$((fail+1))
  fi
}

echo "=== sqssh transport smoke test ==="
run "handshake completes"   "open+user"      "authentication failed"
run "empty whitelist drops" "whitelist+user" "connection timed out"

# SIP-29. A server that has retired envelope version 1 must still be reachable
# by a *default* client, because the default is the version squic emits and
# squic emits version 2. This case exists because it once did not: sqssh's own
# config layer resolved an unset EnvelopeVersion to 1, pinning version 1 on top
# of squic's default, and every default client was locked out of a server that
# had retired it. Nothing else here would have noticed — both cases above pass
# whichever version the client sends, because both servers accept both.
run "default client reaches a v2-only server" "open+user" "authentication failed" \
  "AcceptedEnvelopeVersions 2"
echo "=== pass=$pass fail=$fail ==="
exit "$fail"
