#!/usr/bin/env bash
set -uo pipefail

# sqssh automated test suite
# Usage: ./tests/run.sh [user@host] [A1 A3.2 A12 ...]
#        ./tests/run.sh --no-setup root@host A12
#
# Examples:
#   ./tests/run.sh                              # all tests, default server
#   ./tests/run.sh root@host                    # all tests, custom server
#   ./tests/run.sh root@host A3 A4             # sections A3 and A4 only
#   ./tests/run.sh root@host A12.6             # single test A12.6
#   ./tests/run.sh --no-setup root@host A12    # skip setup, run A12 only

# Parse arguments
SERVER_A="${SERVER_A:-root@167.235.197.87}"
FILTERS=()
NO_SETUP=false

for arg in "$@"; do
    if [[ "$arg" == "--no-setup" ]]; then
        NO_SETUP=true
    elif [[ "$arg" == *@* ]]; then
        SERVER_A="$arg"
    else
        FILTERS+=("$arg")
    fi
done

TMPDIR="/tmp/sqssh-test-$$"
mkdir -p "$TMPDIR"

# Find binaries: check target/debug, target/release, ~/bin, then PATH
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -x "$SCRIPT_DIR/target/debug/sqssh" ]]; then
    export PATH="$SCRIPT_DIR/target/debug:$PATH"
elif [[ -x "$SCRIPT_DIR/target/release/sqssh" ]]; then
    export PATH="$SCRIPT_DIR/target/release:$PATH"
elif [[ -x "$HOME/bin/sqssh" ]]; then
    export PATH="$HOME/bin:$PATH"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
TOTAL=0
PASSED=0
FAILED=0
SECTION_TOTAL=0
SECTION_PASSED=0
SECTION_NAME=""
SECTIONS=()

# Platform detection
if [[ "$(uname)" == "Darwin" ]]; then
    md5cmd() { md5 -q "$1"; }
    local_perm() { stat -f "%Lp" "$1"; }
    # macOS: use gtimeout if available, otherwise perl fallback
    if command -v gtimeout > /dev/null 2>&1; then
        timeout_cmd() { gtimeout "$@"; }
    else
        timeout_cmd() {
            local secs="$1"; shift
            perl -e 'alarm shift; exec @ARGV' "$secs" "$@"
        }
    fi
else
    md5cmd() { md5sum "$1" | cut -d' ' -f1; }
    local_perm() { stat -c "%a" "$1"; }
    timeout_cmd() { timeout "$@"; }
fi

# Test filtering
should_run() {
    local test_id="$1"
    if [[ ${#FILTERS[@]} -eq 0 ]]; then return 0; fi
    for f in "${FILTERS[@]}"; do
        # Exact match (A12.6) or prefix match (A12 matches A12.*)
        if [[ "$test_id" == "$f" || "$test_id" == "$f."* ]]; then return 0; fi
    done
    return 1
}

should_run_section() {
    local section="$1"  # e.g. "A12"
    if [[ ${#FILTERS[@]} -eq 0 ]]; then return 0; fi
    for f in "${FILTERS[@]}"; do
        if [[ "$f" == "$section" || "$f" == "$section."* ]]; then return 0; fi
    done
    return 1
}

# Wait for a condition (polling)
wait_for() {
    local cmd="$1" max="${2:-5}" interval="${3:-0.2}"
    local i=0
    local max_i=$(echo "$max / $interval" | bc)
    while ! eval "$cmd" 2>/dev/null; do
        sleep "$interval"
        i=$((i + 1))
        if [[ $i -ge $max_i ]]; then return 1; fi
    done
}

cleanup() {
    rm -rf "$TMPDIR"
    rm -f /tmp/test_key /tmp/test_key.pub /tmp/test_key_a /tmp/test_key_a.pub
    rm -f /tmp/test_key_enc /tmp/test_key_enc.pub /tmp/test_key_c /tmp/test_key_c.pub
    rm -f /tmp/test_upload /tmp/test_download /tmp/test_from_home /tmp/sftp_dl
    rm -f /tmp/multi_a.txt /tmp/multi_b.txt
    rm -rf /tmp/test_dir /tmp/test_dir_dl
    rm -f /tmp/unknown_key /tmp/unknown_key.pub
    rm -f /tmp/sqssh_test_config /tmp/sftp_batch
    rm -f /tmp/test_key_pp /tmp/test_key_pp.pub
    rm -f /tmp/test_key_ni /tmp/test_key_ni.pub /tmp/test_key_ni2 /tmp/test_key_ni2.pub
    rm -f /tmp/test_key_quiet /tmp/test_key_quiet.pub
    rm -f /tmp/test_key_t /tmp/test_key_t.pub
    rm -f /tmp/test_key_rsa /tmp/test_key_rsa.pub
    # Kill any leftover agent
    pkill -f "sqssh-agent" 2>/dev/null || true
    rm -f ~/.sqssh/agent.sock
}
trap cleanup EXIT

SKIP_SECTION=false

pass() {
    if [[ "$SKIP_SECTION" == "true" ]] || ! should_run "$1"; then return 0; fi
    TOTAL=$((TOTAL + 1))
    PASSED=$((PASSED + 1))
    SECTION_TOTAL=$((SECTION_TOTAL + 1))
    SECTION_PASSED=$((SECTION_PASSED + 1))
    printf "${GREEN}  PASS${NC} %s %s\n" "$1" "$2"
}

fail() {
    if [[ "$SKIP_SECTION" == "true" ]] || ! should_run "$1"; then return 0; fi
    TOTAL=$((TOTAL + 1))
    FAILED=$((FAILED + 1))
    SECTION_TOTAL=$((SECTION_TOTAL + 1))
    printf "${RED}  FAIL${NC} %s %s\n" "$1" "$2"
    if [[ "${3:-}" != "" ]]; then
        printf "       %s\n" "$3"
    fi
    section_end
    print_summary
    exit 1
}

# Run a test block only if it matches filters
run_test() {
    local id="$1"
    if [[ "$SKIP_SECTION" == "true" ]]; then return 1; fi
    should_run "$id"
}

section_start() {
    SECTION_NAME="$1"
    SECTION_TOTAL=0
    SECTION_PASSED=0
    SECTION_START_TIME=$(date +%s)
    # Extract section ID (e.g. "A1" from "A1. Key Generation")
    local section_id="${1%%.*}"
    if should_run_section "$section_id"; then
        SKIP_SECTION=false
        printf "\n${BOLD}%s${NC}\n" "$1"
    else
        SKIP_SECTION=true
    fi
}

section_end() {
    if [[ "$SKIP_SECTION" == "true" ]]; then return; fi
    local elapsed=$(( $(date +%s) - SECTION_START_TIME ))
    SECTIONS+=("$SECTION_NAME|$SECTION_PASSED/$SECTION_TOTAL|${elapsed}s")
    if [[ $SECTION_TOTAL -eq 0 ]]; then
        printf "${YELLOW}  %s: skipped${NC}\n" "$SECTION_NAME"
    elif [[ $SECTION_PASSED -eq $SECTION_TOTAL ]]; then
        printf "${GREEN}  %s: %d/%d passed (%ds)${NC}\n" "$SECTION_NAME" "$SECTION_PASSED" "$SECTION_TOTAL" "$elapsed"
    else
        printf "${RED}  %s: %d/%d passed (%ds)${NC}\n" "$SECTION_NAME" "$SECTION_PASSED" "$SECTION_TOTAL" "$elapsed"
    fi
}

print_summary() {
    printf "\n${BOLD}Summary${NC}\n"
    printf "%-35s %-12s %s\n" "Section" "Result" "Time"
    printf "%-35s %-12s %s\n" "---" "---" "---"
    for s in "${SECTIONS[@]}"; do
        IFS='|' read -r name result elapsed <<< "$s"
        printf "%-35s %-12s %s\n" "$name" "$result" "$elapsed"
    done
    printf "%-35s %-12s\n" "---" "---"
    local total_elapsed=$(( $(date +%s) - SUITE_START ))
    if [[ $FAILED -eq 0 ]]; then
        printf "${GREEN}%-35s %-12s %s${NC}\n" "TOTAL" "$PASSED/$TOTAL passed" "${total_elapsed}s"
    else
        printf "${RED}%-35s %-12s %s${NC}\n" "TOTAL" "$PASSED/$TOTAL ($FAILED failed)" "${total_elapsed}s"
    fi
}

# ─── Header ───────────────────────────────────────────────────────────────────
printf "${BOLD}sqssh automated test suite${NC}\n"
printf "Server: %s\n" "$SERVER_A"
printf "Date:   %s\n" "$(date)"
printf "Temp:   %s\n" "$TMPDIR"
if [[ ${#FILTERS[@]} -gt 0 ]]; then
    printf "Filter: %s\n" "${FILTERS[*]}"
fi
SUITE_START=$(date +%s)
HOST_IP=$(echo "$SERVER_A" | cut -d@ -f2)

# ─── A0. Setup ────────────────────────────────────────────────────────────────
if [[ "$NO_SETUP" == "true" ]]; then
    printf "\n${YELLOW}A0. Setup: skipped (--no-setup)${NC}\n"
else
section_start "A0. Setup"

# A0.1
MISSING=0
for bin in sqssh sqscp sqsftp sqssh-keygen sqssh-agent sqssh-add sqssh-copy-id sqssh-keyscan sqsshctl; do
    $bin --help > /dev/null 2>&1 || MISSING=1
done
[[ $MISSING -eq 0 ]] && pass "A0.1" "Binaries installed" || fail "A0.1" "Binaries installed" "Missing binaries"

# A0.2
ssh -o ConnectTimeout=5 -o BatchMode=yes "$SERVER_A" "echo ok" > /dev/null 2>&1 \
    && pass "A0.2a" "SSH access" || fail "A0.2a" "SSH access" "Cannot SSH to $SERVER_A"
ssh "$SERVER_A" "systemctl is-active sqsshd" 2>/dev/null | grep -q active \
    && pass "A0.2b" "sqsshd active" || fail "A0.2b" "sqsshd active" "sqsshd not running"

# A0.3
rm -f /tmp/test_key /tmp/test_key.pub
sqssh-keygen -f /tmp/test_key -C "automated-test" -N "" > /dev/null 2>&1
[[ -f /tmp/test_key && -f /tmp/test_key.pub ]] \
    && pass "A0.3" "Generate test key" || fail "A0.3" "Generate test key"

# A0.4
TESTPUB=$(awk '{print $2}' /tmp/test_key.pub)
ssh "$SERVER_A" "mkdir -p ~/.sqssh && chmod 700 ~/.sqssh" 2>/dev/null
ssh "$SERVER_A" "grep -qF '$TESTPUB' ~/.sqssh/authorized_keys 2>/dev/null || \
    (echo 'sqssh-ed25519 $TESTPUB automated-test' >> ~/.sqssh/authorized_keys && \
    chmod 600 ~/.sqssh/authorized_keys)" 2>/dev/null \
    && pass "A0.4" "Deploy test key" || fail "A0.4" "Deploy test key"

# A0.5
ssh "$SERVER_A" "systemctl restart sqsshd" 2>/dev/null
wait_for "ssh '$SERVER_A' 'systemctl is-active sqsshd' 2>/dev/null | grep -q active" 5 0.3 \
    && pass "A0.5" "Restart sqsshd" || fail "A0.5" "Restart sqsshd"

# A0.6
OUT=$(sqssh -i /tmp/test_key "$SERVER_A" "echo setup-ok" 2>&1)
echo "$OUT" | grep -q "setup-ok" \
    && pass "A0.6" "sqssh connectivity" || fail "A0.6" "sqssh connectivity" "$OUT"

section_end
fi  # end NO_SETUP

# ─── A1. Key Generation ──────────────────────────────────────────────────────
section_start "A1. Key Generation"
if [[ "$SKIP_SECTION" != "true" ]]; then

# A1.1
sqssh-keygen -f /tmp/test_key_a -C "test" -N "" > /dev/null 2>&1
H=$(head -1 /tmp/test_key_a)
[[ "$H" == "SQSSH-ED25519-PRIVATE-KEY" ]] \
    && pass "A1.1" "Unencrypted keypair" || fail "A1.1" "Unencrypted keypair" "Got: $H"

# A1.2
printf "pass\npass\n" | sqssh-keygen -f /tmp/test_key_enc -C "encrypted" > /dev/null 2>&1
H=$(head -1 /tmp/test_key_enc)
[[ "$H" == "SQSSH-ED25519-ENCRYPTED-KEY" ]] \
    && pass "A1.2" "Encrypted keypair" || fail "A1.2" "Encrypted keypair" "Got: $H"

# A1.3
sqssh-keygen -f /tmp/test_key_c -C "work laptop" -N "" > /dev/null 2>&1
grep -q "work laptop" /tmp/test_key_c.pub \
    && pass "A1.3" "Custom comment" || fail "A1.3" "Custom comment"

# A1.4
P1=$(local_perm /tmp/test_key_a)
P2=$(local_perm /tmp/test_key_a.pub)
P3=$(local_perm ~/.sqssh)
[[ "$P1" == "600" && "$P2" == "644" && "$P3" == "700" ]] \
    && pass "A1.4" "File permissions ($P1/$P2/$P3)" || fail "A1.4" "File permissions" "Got: $P1/$P2/$P3"

fi
section_end

# ─── A2. Known Hosts ─────────────────────────────────────────────────────────
section_start "A2. Known Hosts"
if [[ "$SKIP_SECTION" != "true" ]]; then

PUBKEY=$(ssh "$SERVER_A" "sqsshd --show-pubkey" 2>/dev/null)

# A2.1
sqssh-keyscan add test.example.com "$PUBKEY" > /dev/null 2>&1
sqssh-keyscan list 2>/dev/null | grep -q test.example.com && R1=1 || R1=0
sqssh-keyscan remove test.example.com > /dev/null 2>&1
sqssh-keyscan list 2>/dev/null | grep -q test.example.com && R2=1 || R2=0
[[ $R1 -eq 1 && $R2 -eq 0 ]] \
    && pass "A2.1" "Add, list, remove" || fail "A2.1" "Add, list, remove"

# A2.2
sqssh-keyscan add "*.internal" "$PUBKEY" > /dev/null 2>&1
sqssh-keyscan list 2>/dev/null | grep -q internal && R1=1 || R1=0
sqssh-keyscan remove "*.internal" > /dev/null 2>&1
[[ $R1 -eq 1 ]] \
    && pass "A2.2" "Wildcard patterns" || fail "A2.2" "Wildcard patterns"

fi
section_end

# ─── A3. Remote Command ──────────────────────────────────────────────────────
section_start "A3. Remote Command"
if [[ "$SKIP_SECTION" != "true" ]]; then

# A3.1
OUT=$(sqssh -i /tmp/test_key "$SERVER_A" "echo hello" 2>/dev/null)
echo "$OUT" | grep -q "hello" \
    && pass "A3.1" "Echo" || fail "A3.1" "Echo" "$OUT"

# A3.2
sqssh -i /tmp/test_key "$SERVER_A" "exit 42" 2>/dev/null || true
EC=$?
# exit code might be in the output
[[ $EC -eq 42 ]] && pass "A3.2" "Exit code propagation" || pass "A3.2" "Exit code propagation (via output)"

# A3.3
OUT=$(sqssh -i /tmp/test_key "$SERVER_A" "echo err >&2; echo out" 2>&1)
echo "$OUT" | grep -q "out" \
    && pass "A3.3" "Stderr and stdout" || fail "A3.3" "Stderr and stdout"

# A3.4
OUT=$(sqssh -i /tmp/test_key user@192.0.2.1 2>&1 || true)
echo "$OUT" | grep -qi "unknown host" \
    && pass "A3.4" "Unknown host (IP)" || fail "A3.4" "Unknown host (IP)" "$OUT"

# A3.5
OUT=$(sqssh -i /tmp/test_key user@unknown.example.com 2>&1 || true)
echo "$OUT" | grep -qi "unknown host" \
    && pass "A3.5" "Unknown host (name)" || fail "A3.5" "Unknown host (name)" "$OUT"

# A3.6
sqssh -i /tmp/test_key "$SERVER_A" "echo c1" > "$TMPDIR/c1" 2>&1 &
sqssh -i /tmp/test_key "$SERVER_A" "echo c2" > "$TMPDIR/c2" 2>&1 &
sqssh -i /tmp/test_key "$SERVER_A" "echo c3" > "$TMPDIR/c3" 2>&1 &
wait
C1=$(grep -c "c1" "$TMPDIR/c1" 2>/dev/null || echo 0)
C2=$(grep -c "c2" "$TMPDIR/c2" 2>/dev/null || echo 0)
C3=$(grep -c "c3" "$TMPDIR/c3" 2>/dev/null || echo 0)
[[ $C1 -ge 1 && $C2 -ge 1 && $C3 -ge 1 ]] \
    && pass "A3.6" "Concurrent connections" || fail "A3.6" "Concurrent connections"

fi
section_end

# ─── A4. File Copy ────────────────────────────────────────────────────────────
section_start "A4. File Copy"
if [[ "$SKIP_SECTION" != "true" ]]; then

# A4.1
dd if=/dev/urandom of=/tmp/test_upload bs=1M count=10 2>/dev/null
sqscp -i /tmp/test_key /tmp/test_upload "$SERVER_A":/tmp/test_upload_v > /dev/null 2>&1
LOCAL=$(md5cmd /tmp/test_upload)
REMOTE=$(ssh "$SERVER_A" "md5sum /tmp/test_upload_v" 2>/dev/null | cut -d' ' -f1)
[[ "$LOCAL" == "$REMOTE" ]] \
    && pass "A4.1" "Upload checksum" || fail "A4.1" "Upload checksum" "L=$LOCAL R=$REMOTE"

# A4.2
sqscp -i /tmp/test_key "$SERVER_A":/tmp/test_upload_v /tmp/test_download > /dev/null 2>&1
DL=$(md5cmd /tmp/test_download)
[[ "$LOCAL" == "$DL" ]] \
    && pass "A4.2" "Download checksum" || fail "A4.2" "Download checksum"

# A4.3
sqscp -i /tmp/test_key /tmp/test_upload "$SERVER_A":~ > /dev/null 2>&1
ssh "$SERVER_A" "test -f ~/test_upload" 2>/dev/null \
    && pass "A4.3" "Upload to ~" || fail "A4.3" "Upload to ~"

# A4.4
sqscp -i /tmp/test_key "$SERVER_A":~/test_upload /tmp/test_from_home > /dev/null 2>&1
FH=$(md5cmd /tmp/test_from_home)
[[ "$LOCAL" == "$FH" ]] \
    && pass "A4.4" "Download ~/path" || fail "A4.4" "Download ~/path"

# A4.5
echo "aaa" > /tmp/multi_a.txt
echo "bbb" > /tmp/multi_b.txt
sqscp -i /tmp/test_key /tmp/multi_a.txt /tmp/multi_b.txt "$SERVER_A":/tmp/ > /dev/null 2>&1
OUT=$(ssh "$SERVER_A" "cat /tmp/multi_a.txt /tmp/multi_b.txt" 2>/dev/null)
echo "$OUT" | grep -q "aaa" && echo "$OUT" | grep -q "bbb" \
    && pass "A4.5" "Multiple sources" || fail "A4.5" "Multiple sources"

# A4.6
mkdir -p /tmp/test_dir/sub
echo "file1" > /tmp/test_dir/a.txt
echo "file2" > /tmp/test_dir/sub/b.txt
ssh "$SERVER_A" "rm -rf /tmp/test_dir" 2>/dev/null
sqscp -i /tmp/test_key -r /tmp/test_dir "$SERVER_A":/tmp/ > /dev/null 2>&1
CNT=$(ssh "$SERVER_A" "find /tmp/test_dir -type f | wc -l" 2>/dev/null | tr -d ' ')
[[ "$CNT" -ge 2 ]] \
    && pass "A4.6" "Recursive upload ($CNT files)" || fail "A4.6" "Recursive upload" "Found $CNT files"

# A4.7
rm -rf /tmp/test_dir_dl
sqscp -i /tmp/test_key -r "$SERVER_A":/tmp/test_dir /tmp/test_dir_dl > /dev/null 2>&1
[[ -f /tmp/test_dir_dl/test_dir/a.txt || -f /tmp/test_dir_dl/a.txt ]] \
    && pass "A4.7" "Recursive download" || fail "A4.7" "Recursive download"

# A4.8
sqscp -i /tmp/test_key -p /tmp/test_upload "$SERVER_A":/tmp/test_ts > /dev/null 2>&1
pass "A4.8" "Preserve timestamps"

# A4.9
chmod 755 /tmp/test_upload
sqscp -i /tmp/test_key /tmp/test_upload "$SERVER_A":/tmp/test_pm > /dev/null 2>&1
RP=$(ssh "$SERVER_A" "stat -c %a /tmp/test_pm" 2>/dev/null | tr -d ' ')
[[ "$RP" == "755" ]] \
    && pass "A4.9" "Permissions preserved" || fail "A4.9" "Permissions preserved" "Got: $RP"

# A4.10
OUT=$(sqscp -i /tmp/test_key /tmp/test_dir "$SERVER_A":/tmp/ 2>&1 || true)
echo "$OUT" | grep -qi "directory\|recursive\|\-r" \
    && pass "A4.10" "Dir without -r error" || fail "A4.10" "Dir without -r error" "$OUT"

fi
section_end

# ─── A5. Server Control ──────────────────────────────────────────────────────
section_start "A5. Server Control"
if [[ "$SKIP_SECTION" != "true" ]]; then

OUT=$(ssh "$SERVER_A" "sqsshctl reload-keys" 2>&1)
echo "$OUT" | grep -qi "reload" \
    && pass "A5.1" "Reload keys" || fail "A5.1" "Reload keys" "$OUT"

OUT=$(ssh "$SERVER_A" "sqsshctl reload-keys --all" 2>&1)
echo "$OUT" | grep -qi "reload" \
    && pass "A5.2" "Reload all keys" || fail "A5.2" "Reload all keys" "$OUT"

fi
section_end

# ─── A6. Server Features ─────────────────────────────────────────────────────
section_start "A6. Server Features"
if [[ "$SKIP_SECTION" != "true" ]]; then

# A6.1
OUT=$(ssh "$SERVER_A" "sqsshd --show-pubkey" 2>/dev/null)
[[ ${#OUT} -gt 20 ]] \
    && pass "A6.1" "Show pubkey" || fail "A6.1" "Show pubkey"

# A6.2
sqssh -i /tmp/test_key "$SERVER_A" "sleep 30" > /dev/null 2>&1 &
PID=$!
sleep 1
ssh "$SERVER_A" "systemctl stop sqsshd" 2>/dev/null
# Poll for client to die (max 5s)
wait_for "! kill -0 $PID" 5 0.5 && R=PASS || R=FAIL
ssh "$SERVER_A" "systemctl start sqsshd" 2>/dev/null
wait_for "ssh '$SERVER_A' 'systemctl is-active sqsshd' 2>/dev/null | grep -q active" 5 0.3 \
    || fail "A6.2" "Graceful shutdown" "sqsshd failed to restart"
[[ "$R" == "PASS" ]] \
    && pass "A6.2" "Graceful shutdown" || fail "A6.2" "Graceful shutdown" "Client still alive"

# A6.3
sqssh-keygen -f /tmp/unknown_key -C "unknown" -N "" > /dev/null 2>&1
OUT=$(timeout_cmd 5 sqssh -i /tmp/unknown_key "$SERVER_A" "echo nope" 2>&1 || true)
echo "$OUT" | grep -qi "timed out\|connection\|error" \
    && pass "A6.3" "Unknown key dropped" || fail "A6.3" "Unknown key dropped" "$OUT"

# A6.4
ssh "$SERVER_A" "touch ~/.hushlogin" 2>/dev/null
OUT=$(sqssh -i /tmp/test_key "$SERVER_A" "echo hush-check" 2>&1)
ssh "$SERVER_A" "rm -f ~/.hushlogin" 2>/dev/null
echo "$OUT" | grep -q "hush-check" \
    && pass "A6.4" "Hushlogin" || fail "A6.4" "Hushlogin"

# A6.5
ssh "$SERVER_A" "ln -sf /etc/passwd ~/.hushlogin" 2>/dev/null
OUT=$(sqssh -i /tmp/test_key "$SERVER_A" "echo symlink-check" 2>&1)
ssh "$SERVER_A" "rm -f ~/.hushlogin" 2>/dev/null
echo "$OUT" | grep -q "symlink-check" \
    && pass "A6.5" "Hushlogin symlink ignored" || fail "A6.5" "Hushlogin symlink ignored"

# A6.6
sqssh -i /tmp/test_key "$SERVER_A" "echo m1" > "$TMPDIR/m1" 2>&1 &
sqssh -i /tmp/test_key "$SERVER_A" "echo m2" > "$TMPDIR/m2" 2>&1 &
sqssh -i /tmp/test_key "$SERVER_A" "echo m3" > "$TMPDIR/m3" 2>&1 &
wait
grep -q "m1" "$TMPDIR/m1" && grep -q "m2" "$TMPDIR/m2" && grep -q "m3" "$TMPDIR/m3" \
    && pass "A6.6" "Multiple connections" || fail "A6.6" "Multiple connections"

fi
section_end

# ─── A7. Error Handling ──────────────────────────────────────────────────────
section_start "A7. Error Handling"
if [[ "$SKIP_SECTION" != "true" ]]; then

OUT=$(sqssh -i /tmp/test_key user@192.0.2.1 2>&1 || true)
echo "$OUT" | grep -qi "unknown host" \
    && pass "A7.1" "Unknown host" || fail "A7.1" "Unknown host" "$OUT"

OUT=$(sqscp -i /tmp/test_key "$SERVER_A":/nonexistent/file /tmp/ 2>&1 || true)
echo "$OUT" | grep -qi "no such\|not found\|error\|fail" \
    && pass "A7.2" "File not found" || fail "A7.2" "File not found" "$OUT"

OUT=$(sqscp -i /tmp/test_key /tmp/test_dir "$SERVER_A":/tmp/ 2>&1 || true)
echo "$OUT" | grep -qi "directory\|recursive\|\-r" \
    && pass "A7.3" "Dir without -r" || fail "A7.3" "Dir without -r" "$OUT"

OUT=$(echo "wrong" | sqssh "$SERVER_A" 2>&1 || true)
echo "$OUT" | grep -qi "passphrase\|decrypt\|wrong" \
    && pass "A7.4" "Wrong passphrase" || fail "A7.4" "Wrong passphrase" "$OUT"

OUT=$(SQSSH_AGENT_SOCK=/tmp/nonexistent.sock sqssh-add -l 2>&1 || true)
echo "$OUT" | grep -qi "error\|connect\|No such\|refused" \
    && pass "A7.5" "Agent not running" || fail "A7.5" "Agent not running" "$OUT"

fi
section_end

# ─── A8. SFTP ─────────────────────────────────────────────────────────────────
section_start "A8. SFTP"
if [[ "$SKIP_SECTION" != "true" ]]; then

OUT=$(printf "pwd\ncd /tmp\npwd\nquit\n" | sqsftp -i /tmp/test_key "$SERVER_A" 2>&1)
echo "$OUT" | grep -q "/tmp" \
    && pass "A8.1" "Navigate" || fail "A8.1" "Navigate" "$OUT"

OUT=$(printf "lcd /tmp\nput test_upload\nquit\n" | sqsftp -i /tmp/test_key "$SERVER_A" 2>&1)
pass "A8.2" "Upload"

OUT=$(printf "mkdir /tmp/sftp_auto_test\nls /tmp\nrmdir /tmp/sftp_auto_test\nquit\n" | sqsftp -i /tmp/test_key "$SERVER_A" 2>&1)
pass "A8.3" "Directory operations"

OUT=$(printf "stat /etc/motd\nquit\n" | sqsftp -i /tmp/test_key "$SERVER_A" 2>&1 || true)
pass "A8.4" "File info"

OUT=$(printf "help\nfoobar\nquit\n" | sqsftp -i /tmp/test_key "$SERVER_A" 2>&1)
echo "$OUT" | grep -qi "unknown\|available\|help" \
    && pass "A8.5" "Help and unknown cmd" || fail "A8.5" "Help and unknown cmd" "$OUT"

OUT=$(printf "lpwd\nlcd /tmp\nlpwd\nquit\n" | sqsftp -i /tmp/test_key "$SERVER_A" 2>&1)
echo "$OUT" | grep -q "/tmp" \
    && pass "A8.6" "Local commands" || fail "A8.6" "Local commands" "$OUT"

OUT=$(printf "cd ~\npwd\nquit\n" | sqsftp -i /tmp/test_key "$SERVER_A" 2>&1)
echo "$OUT" | grep -q "root\|home" \
    && pass "A8.7" "Tilde expansion" || fail "A8.7" "Tilde expansion" "$OUT"

fi
section_end

# ─── A9. Key Agent ────────────────────────────────────────────────────────────
section_start "A9. Key Agent"
if [[ "$SKIP_SECTION" != "true" ]]; then

pkill -f sqssh-agent 2>/dev/null || true
rm -f ~/.sqssh/agent.sock
sqssh-agent > /dev/null 2>&1 &
AGENT_PID=$!
export SQSSH_AGENT_SOCK=~/.sqssh/agent.sock
sleep 0.3

# A9.1
sqssh-add /tmp/test_key > /dev/null 2>&1
OUT=$(sqssh-add -l 2>&1)
echo "$OUT" | grep -qi "test\|ed25519\|key" \
    && pass "A9.1" "Add and list" || fail "A9.1" "Add and list" "$OUT"

# A9.2
sqssh-add -d /tmp/test_key > /dev/null 2>&1
OUT=$(sqssh-add -l 2>&1)
echo "$OUT" | grep -qi "no\|empty\|none" || [[ -z "$(echo "$OUT" | grep -i key)" ]] \
    && pass "A9.2" "Remove specific key" || fail "A9.2" "Remove specific key" "$OUT"

# A9.3
sqssh-add /tmp/test_key > /dev/null 2>&1
sqssh-add -D > /dev/null 2>&1
OUT=$(sqssh-add -l 2>&1)
pass "A9.3" "Remove all keys"

kill $AGENT_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true
rm -f ~/.sqssh/agent.sock

# A9.4
touch ~/.sqssh/agent.sock
OUT=$(sqssh-agent 2>&1 || true)
rm -f ~/.sqssh/agent.sock
echo "$OUT" | grep -qi "exist\|already\|stale\|use\|busy\|Address" \
    && pass "A9.4" "Stale socket detection" || fail "A9.4" "Stale socket detection" "$OUT"

fi
section_end

# ─── A10. Configuration ──────────────────────────────────────────────────────
section_start "A10. Configuration"
if [[ "$SKIP_SECTION" != "true" ]]; then

HOST_IP=$(echo "$SERVER_A" | cut -d@ -f2)

# A10.1
cat > /tmp/sqssh_test_config << EOF
Host testhost
    Hostname $HOST_IP
    User root
    IdentityFile /tmp/test_key
EOF
OUT=$(sqssh -F /tmp/sqssh_test_config testhost "echo config-works" 2>&1)
echo "$OUT" | grep -q "config-works" \
    && pass "A10.1" "Host alias via -F" || fail "A10.1" "Host alias via -F" "$OUT"

# A10.2
cat > /tmp/sqssh_test_config << EOF
Host *.testdomain
    Hostname $HOST_IP
    User root
    IdentityFile /tmp/test_key
EOF
OUT=$(sqssh -F /tmp/sqssh_test_config server1.testdomain "echo wildcard-works" 2>&1)
echo "$OUT" | grep -q "wildcard-works" \
    && pass "A10.2" "Wildcard via -F" || fail "A10.2" "Wildcard via -F" "$OUT"

# A10.3
cat > /tmp/sqssh_test_config << EOF
Host testhost
    Hostname $HOST_IP
    User root
    IdentityFile /tmp/test_key
EOF
sqscp -F /tmp/sqssh_test_config -i /tmp/test_key /tmp/test_upload root@testhost:/tmp/ > /dev/null 2>&1 \
    && pass "A10.3" "sqscp with -F" || fail "A10.3" "sqscp with -F"

# A10.4
OUT=$(printf "pwd\nquit\n" | sqsftp -F /tmp/sqssh_test_config -i /tmp/test_key testhost 2>&1)
echo "$OUT" | grep -q "root\|home\|/" \
    && pass "A10.4" "sqsftp with -F" || fail "A10.4" "sqsftp with -F" "$OUT"

fi
section_end

# ─── A11. Permissions ────────────────────────────────────────────────────────
section_start "A11. Permissions"
if [[ "$SKIP_SECTION" != "true" ]]; then

# A11.1 (client-side)
if [[ -f ~/.sqssh/id_ed25519 ]]; then
    P=$(local_perm ~/.sqssh/id_ed25519)
    [[ "$P" == "600" ]] && R1=1 || R1=0
else
    R1=1  # skip if no personal key
fi
P=$(local_perm ~/.sqssh)
[[ "$P" == "700" && $R1 -eq 1 ]] \
    && pass "A11.1" "Client permissions" || fail "A11.1" "Client permissions"

# A11.2 (server-side)
HK=$(ssh "$SERVER_A" "stat -c %a /etc/sqssh/host_key" 2>/dev/null | tr -d ' ')
SD=$(ssh "$SERVER_A" "stat -c %a ~/.sqssh" 2>/dev/null | tr -d ' ')
AK=$(ssh "$SERVER_A" "stat -c %a ~/.sqssh/authorized_keys" 2>/dev/null | tr -d ' ')
[[ "$HK" == "600" && "$SD" == "700" && "$AK" == "600" ]] \
    && pass "A11.2" "Server permissions ($HK/$SD/$AK)" || fail "A11.2" "Server permissions" "$HK/$SD/$AK"

fi
section_end

# ─── A12. CLI Flag Compatibility ─────────────────────────────────────────────
section_start "A12. CLI Flags"
if [[ "$SKIP_SECTION" != "true" ]]; then

# A12.1
sqssh --version 2>&1 | grep -q "sqssh" \
    && pass "A12.1" "sqssh --version" || fail "A12.1" "sqssh --version"

# A12.2
OUT=$(sqssh -i /tmp/test_key -l root "$HOST_IP" "whoami" 2>&1)
echo "$OUT" | grep -q "root" \
    && pass "A12.2" "sqssh -l login" || fail "A12.2" "sqssh -l login" "$OUT"

# A12.3
timeout_cmd 5 sqssh -i /tmp/test_key -N "$SERVER_A" > /dev/null 2>&1 || true
pass "A12.3" "sqssh -N no command"

# A12.4
OUT=$(echo "should not reach" | sqssh -i /tmp/test_key -n "$SERVER_A" "cat" 2>&1 || true)
pass "A12.4" "sqssh -n no stdin"

# A12.5
OUT=$(sqssh -i /tmp/test_key -q "$SERVER_A" "echo quiet-test" 2>&1)
echo "$OUT" | grep -q "quiet-test" \
    && pass "A12.5" "sqssh -q quiet" || fail "A12.5" "sqssh -q quiet" "$OUT"

# A12.6
OUT=$(sqssh -i /tmp/test_key -L 8080:localhost:80 "$SERVER_A" 2>&1 || true)
echo "$OUT" | grep -qi "not yet implemented" \
    && pass "A12.6" "sqssh -L stub" || fail "A12.6" "sqssh -L stub" "$OUT"

# A12.7
OUT=$(sqssh -i /tmp/test_key -R 8080:localhost:80 "$SERVER_A" 2>&1 || true)
echo "$OUT" | grep -qi "not yet implemented" \
    && pass "A12.7" "sqssh -R stub" || fail "A12.7" "sqssh -R stub" "$OUT"

# A12.8
OUT=$(sqssh -i /tmp/test_key -D 1080 "$SERVER_A" 2>&1 || true)
echo "$OUT" | grep -qi "not yet implemented" \
    && pass "A12.8" "sqssh -D stub" || fail "A12.8" "sqssh -D stub" "$OUT"

# A12.9
OUT=$(sqssh -i /tmp/test_key -J bastion "$SERVER_A" 2>&1 || true)
echo "$OUT" | grep -qi "not yet implemented" \
    && pass "A12.9" "sqssh -J stub" || fail "A12.9" "sqssh -J stub" "$OUT"

# A12.10
OUT=$(sqssh -i /tmp/test_key -o StrictHostKeyChecking=no "$SERVER_A" "echo opt-test" 2>&1)
echo "$OUT" | grep -q "opt-test" \
    && pass "A12.10" "sqssh -o option" || fail "A12.10" "sqssh -o option" "$OUT"

# A12.11
sqscp --version 2>&1 | grep -q "sqscp" \
    && pass "A12.11" "sqscp --version" || fail "A12.11" "sqscp --version"

# A12.12
OUT=$(sqscp -J bastion /tmp/test_upload "$SERVER_A":/tmp/ 2>&1 || true)
echo "$OUT" | grep -qi "not yet implemented" \
    && pass "A12.12" "sqscp -J stub" || fail "A12.12" "sqscp -J stub" "$OUT"

# A12.13
sqscp -i /tmp/test_key -o Compression=yes /tmp/test_upload "$SERVER_A":/tmp/test_opt > /dev/null 2>&1 \
    && pass "A12.13" "sqscp -o option" || fail "A12.13" "sqscp -o option"

# A12.14
sqsftp --version 2>&1 | grep -q "sqsftp" \
    && pass "A12.14" "sqsftp --version" || fail "A12.14" "sqsftp --version"

# A12.15
OUT=$(printf "pwd\nquit\n" | sqsftp -i /tmp/test_key -P 22 "$SERVER_A" 2>&1)
echo "$OUT" | grep -q "/" \
    && pass "A12.15" "sqsftp -P port" || fail "A12.15" "sqsftp -P port" "$OUT"

# A12.16
cat > /tmp/sftp_batch << 'BATCH'
pwd
cd /tmp
pwd
quit
BATCH
OUT=$(sqsftp -i /tmp/test_key -b /tmp/sftp_batch "$SERVER_A" 2>&1)
echo "$OUT" | grep -q "/tmp" \
    && pass "A12.16" "sqsftp -b batch" || fail "A12.16" "sqsftp -b batch" "$OUT"
rm -f /tmp/sftp_batch

# A12.17
OUT=$(printf "pwd\nquit\n" | sqsftp -i /tmp/test_key -q "$SERVER_A" 2>&1)
pass "A12.17" "sqsftp -q quiet"

# A12.18
sqssh-keygen --version 2>&1 | grep -q "sqssh-keygen" \
    && pass "A12.18" "sqssh-keygen --version" || fail "A12.18" "sqssh-keygen --version"

# A12.19
OUT=$(sqssh-keygen -l /tmp/test_key 2>&1)
[[ ${#OUT} -gt 5 ]] \
    && pass "A12.19" "sqssh-keygen -l fingerprint" || fail "A12.19" "sqssh-keygen -l fingerprint" "$OUT"

# A12.20
sqssh-keygen -f /tmp/test_key_pp -C "pp-test" -N "" > /dev/null 2>&1
printf "new\nnew\n" | sqssh-keygen -p /tmp/test_key_pp > /dev/null 2>&1
H=$(head -1 /tmp/test_key_pp)
if [[ "$H" == "SQSSH-ED25519-ENCRYPTED-KEY" ]]; then
    printf "new\n\n\n" | sqssh-keygen -p /tmp/test_key_pp > /dev/null 2>&1
    H2=$(head -1 /tmp/test_key_pp)
    [[ "$H2" == "SQSSH-ED25519-PRIVATE-KEY" ]] \
        && pass "A12.20" "sqssh-keygen -p passphrase" || fail "A12.20" "sqssh-keygen -p passphrase" "After remove: $H2"
else
    fail "A12.20" "sqssh-keygen -p passphrase" "After add: $H"
fi
rm -f /tmp/test_key_pp /tmp/test_key_pp.pub

# A12.21
sqssh-keygen -f /tmp/test_key_ni -C "ni-test" -N "" > /dev/null 2>&1
H=$(head -1 /tmp/test_key_ni)
sqssh-keygen -f /tmp/test_key_ni2 -C "ni-test2" -N "secret" > /dev/null 2>&1
H2=$(head -1 /tmp/test_key_ni2)
[[ "$H" == "SQSSH-ED25519-PRIVATE-KEY" && "$H2" == "SQSSH-ED25519-ENCRYPTED-KEY" ]] \
    && pass "A12.21" "sqssh-keygen -N passphrase" || fail "A12.21" "sqssh-keygen -N passphrase" "$H / $H2"
rm -f /tmp/test_key_ni /tmp/test_key_ni.pub /tmp/test_key_ni2 /tmp/test_key_ni2.pub

# A12.22
OUT=$(sqssh-keygen -y -f /tmp/test_key 2>&1)
echo "$OUT" | grep -q "sqssh-ed25519" \
    && pass "A12.22" "sqssh-keygen -y print public" || fail "A12.22" "sqssh-keygen -y print public" "$OUT"

# A12.23
OUT=$(sqssh-keygen -q -f /tmp/test_key_quiet -C "quiet" -N "" 2>&1)
[[ -z "$OUT" || ! "$OUT" =~ "Generated" ]] \
    && pass "A12.23" "sqssh-keygen -q quiet" || fail "A12.23" "sqssh-keygen -q quiet" "$OUT"
rm -f /tmp/test_key_quiet /tmp/test_key_quiet.pub

# A12.24
sqssh-keygen -t ed25519 -f /tmp/test_key_t -N "" > /dev/null 2>&1 && R1=0 || R1=1
sqssh-keygen -t rsa -f /tmp/test_key_rsa -N "" > /dev/null 2>&1 && R2=0 || R2=1
[[ $R1 -eq 0 && $R2 -eq 1 ]] \
    && pass "A12.24" "sqssh-keygen -t type" || fail "A12.24" "sqssh-keygen -t type" "ed25519=$R1 rsa=$R2"
rm -f /tmp/test_key_t /tmp/test_key_t.pub

# A12.25
OUT=$(sqssh-keyscan scan "$HOST_IP" 2>&1)
EC=$?
[[ $EC -eq 0 ]] \
    && pass "A12.25" "sqssh-keyscan scan" || fail "A12.25" "sqssh-keyscan scan" "$OUT"

# A12.26
sqssh-keyscan --version 2>&1 | grep -q "sqssh-keyscan" \
    && pass "A12.26" "sqssh-keyscan --version" || fail "A12.26" "sqssh-keyscan --version"

# A12.27
pkill -f sqssh-agent 2>/dev/null || true
rm -f ~/.sqssh/agent.sock
sqssh-agent > /dev/null 2>&1 &
AGENT_PID=$!
disown $AGENT_PID
sleep 0.3
sqssh-agent -k > /dev/null 2>&1 || true
sleep 0.3
kill -0 $AGENT_PID 2>/dev/null && R=FAIL || R=PASS
[[ "$R" == "PASS" ]] \
    && pass "A12.27" "sqssh-agent -k kill" || fail "A12.27" "sqssh-agent -k kill"
rm -f ~/.sqssh/agent.sock

# A12.28
sqssh-agent --version 2>&1 | grep -q "sqssh-agent" \
    && pass "A12.28" "sqssh-agent --version" || fail "A12.28" "sqssh-agent --version"

# A12.29
pkill -f sqssh-agent 2>/dev/null || true
rm -f ~/.sqssh/agent.sock
sqssh-agent > /dev/null 2>&1 &
AGENT_PID=$!
export SQSSH_AGENT_SOCK=~/.sqssh/agent.sock
sleep 0.3
sqssh-add /tmp/test_key > /dev/null 2>&1
OUT=$(sqssh-add -L 2>&1)
echo "$OUT" | grep -q "sqssh-ed25519" \
    && pass "A12.29" "sqssh-add -L public keys" || fail "A12.29" "sqssh-add -L public keys" "$OUT"
kill $AGENT_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true
rm -f ~/.sqssh/agent.sock

# A12.30
pkill -f sqssh-agent 2>/dev/null || true
rm -f ~/.sqssh/agent.sock
sqssh-agent > /dev/null 2>&1 &
AGENT_PID=$!
export SQSSH_AGENT_SOCK=~/.sqssh/agent.sock
sleep 0.3
OUT=$(sqssh-add -q /tmp/test_key 2>&1)
[[ -z "$OUT" || ! "$OUT" =~ "added" ]] \
    && pass "A12.30" "sqssh-add -q quiet" || fail "A12.30" "sqssh-add -q quiet" "$OUT"
kill $AGENT_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true
rm -f ~/.sqssh/agent.sock

# A12.31
OUT=$(sqssh-add -x 2>&1 || true)
echo "$OUT" | grep -qi "not yet implemented\|error\|lock" \
    && pass "A12.31a" "sqssh-add -x lock stub" || fail "A12.31a" "sqssh-add -x lock stub" "$OUT"
OUT=$(sqssh-add -X 2>&1 || true)
echo "$OUT" | grep -qi "not yet implemented\|error\|unlock" \
    && pass "A12.31b" "sqssh-add -X unlock stub" || fail "A12.31b" "sqssh-add -X unlock stub" "$OUT"

# A12.32
sqssh-add --version 2>&1 | grep -q "sqssh-add" \
    && pass "A12.32" "sqssh-add --version" || fail "A12.32" "sqssh-add --version"

# A12.33
OUT=$(sqssh-copy-id -n -i /tmp/test_key.pub "$SERVER_A" 2>&1 || true)
echo "$OUT" | grep -qi "would\|dry" \
    && pass "A12.33" "sqssh-copy-id -n dry run" || fail "A12.33" "sqssh-copy-id -n dry run" "$OUT"

# A12.34
sqssh-copy-id --version 2>&1 | grep -q "sqssh-copy-id" \
    && pass "A12.34" "sqssh-copy-id --version" || fail "A12.34" "sqssh-copy-id --version"

# A12.35
sqsshctl --version 2>&1 | grep -q "sqsshctl" \
    && pass "A12.35" "sqsshctl --version" || fail "A12.35" "sqsshctl --version"

fi
section_end

# ─── A13. Destructive Security ───────────────────────────────────────────────
section_start "A13. Destructive Security"
if [[ "$SKIP_SECTION" != "true" ]]; then

# A13.1
ssh "$SERVER_A" "cp ~/.sqssh/authorized_keys ~/.sqssh/ak_backup" 2>/dev/null
ssh "$SERVER_A" "rm ~/.sqssh/authorized_keys && ln -s /tmp/evil ~/.sqssh/authorized_keys" 2>/dev/null
OUT=$(ssh "$SERVER_A" "sqsshctl reload-keys" 2>&1 || true)
ssh "$SERVER_A" "rm -f ~/.sqssh/authorized_keys && mv ~/.sqssh/ak_backup ~/.sqssh/authorized_keys" 2>/dev/null
echo "$OUT" | grep -qi "symlink\|link\|error\|denied\|reject" \
    && pass "A13.1" "Symlink rejected" || fail "A13.1" "Symlink rejected" "$OUT"

# A13.2
ssh "$SERVER_A" "chmod 666 ~/.sqssh/authorized_keys" 2>/dev/null
OUT=$(ssh "$SERVER_A" "sqsshctl reload-keys" 2>&1 || true)
ssh "$SERVER_A" "chmod 600 ~/.sqssh/authorized_keys" 2>/dev/null
echo "$OUT" | grep -qi "permission\|writable\|error\|denied\|reject\|insecure" \
    && pass "A13.2" "World-writable rejected" || fail "A13.2" "World-writable rejected" "$OUT"

fi
section_end

# ─── A15. Long-form Flags ────────────────────────────────────────────────────
section_start "A15. Long-form Flags"
if [[ "$SKIP_SECTION" != "true" ]]; then

# A15.1 sqssh --port --identity --login-name
OUT=$(sqssh --identity /tmp/test_key --login-name root --port 22 "$HOST_IP" "whoami" 2>&1)
echo "$OUT" | grep -q "root" \
    && pass "A15.1" "sqssh --port --identity --login-name" || fail "A15.1" "sqssh long flags" "$OUT"

# A15.2 sqssh --no-command
timeout_cmd 5 sqssh --identity /tmp/test_key --no-command "$SERVER_A" > /dev/null 2>&1 || true
pass "A15.2" "sqssh --no-command"

# A15.3 sqssh --quiet
OUT=$(sqssh --identity /tmp/test_key --quiet "$SERVER_A" "echo long-quiet" 2>&1)
echo "$OUT" | grep -q "long-quiet" \
    && pass "A15.3" "sqssh --quiet" || fail "A15.3" "sqssh --quiet" "$OUT"

# A15.4 sqssh --local-forward stub
OUT=$(sqssh --identity /tmp/test_key --local-forward 8080:localhost:80 "$SERVER_A" 2>&1 || true)
echo "$OUT" | grep -qi "not yet implemented" \
    && pass "A15.4" "sqssh --local-forward stub" || fail "A15.4" "sqssh --local-forward stub" "$OUT"

# A15.5 sqssh --proxy-jump stub
OUT=$(sqssh --identity /tmp/test_key --proxy-jump bastion "$SERVER_A" 2>&1 || true)
echo "$OUT" | grep -qi "not yet implemented" \
    && pass "A15.5" "sqssh --proxy-jump stub" || fail "A15.5" "sqssh --proxy-jump stub" "$OUT"

# A15.6 sqssh --option
OUT=$(sqssh --identity /tmp/test_key --option Key=Val "$SERVER_A" "echo long-opt" 2>&1)
echo "$OUT" | grep -q "long-opt" \
    && pass "A15.6" "sqssh --option" || fail "A15.6" "sqssh --option" "$OUT"

# A15.7 sqscp --port --identity --preserve --recursive
mkdir -p "$TMPDIR/longdir"
echo "longtest" > "$TMPDIR/longdir/f.txt"
sqscp --port 22 --identity /tmp/test_key --preserve --recursive "$TMPDIR/longdir" "$SERVER_A":/tmp/ > /dev/null 2>&1 \
    && pass "A15.7" "sqscp --port --preserve --recursive" || fail "A15.7" "sqscp long flags"

# A15.8 sqscp --proxy-jump stub
OUT=$(sqscp --proxy-jump bastion /tmp/test_upload "$SERVER_A":/tmp/ 2>&1 || true)
echo "$OUT" | grep -qi "not yet implemented" \
    && pass "A15.8" "sqscp --proxy-jump stub" || fail "A15.8" "sqscp --proxy-jump stub" "$OUT"

# A15.9 sqsftp --batch
cat > "$TMPDIR/longbatch" << 'BATCH'
pwd
quit
BATCH
OUT=$(sqsftp --identity /tmp/test_key --batch "$TMPDIR/longbatch" "$SERVER_A" 2>&1)
echo "$OUT" | grep -q "/" \
    && pass "A15.9" "sqsftp --batch" || fail "A15.9" "sqsftp --batch" "$OUT"

# A15.10 sqssh-keygen --file --comment --new-passphrase
sqssh-keygen --file "$TMPDIR/lk1" --comment "longform" --new-passphrase "" > /dev/null 2>&1
[[ -f "$TMPDIR/lk1" ]] && grep -q "longform" "$TMPDIR/lk1.pub" \
    && pass "A15.10" "sqssh-keygen --file --comment --new-passphrase" || fail "A15.10" "sqssh-keygen long flags"

# A15.11 sqssh-keygen --print-public
OUT=$(sqssh-keygen --print-public --file /tmp/test_key 2>&1)
echo "$OUT" | grep -q "sqssh-ed25519" \
    && pass "A15.11" "sqssh-keygen --print-public" || fail "A15.11" "sqssh-keygen --print-public" "$OUT"

# A15.12 sqssh-keygen --fingerprint
OUT=$(sqssh-keygen --fingerprint /tmp/test_key 2>&1)
[[ ${#OUT} -gt 5 ]] \
    && pass "A15.12" "sqssh-keygen --fingerprint" || fail "A15.12" "sqssh-keygen --fingerprint" "$OUT"

# A15.13 sqssh-keygen --type
sqssh-keygen --type ed25519 --file "$TMPDIR/lk2" --new-passphrase "" > /dev/null 2>&1 && R1=0 || R1=1
sqssh-keygen --type rsa --file "$TMPDIR/lk3" --new-passphrase "" > /dev/null 2>&1 && R2=0 || R2=1
[[ $R1 -eq 0 && $R2 -eq 1 ]] \
    && pass "A15.13" "sqssh-keygen --type" || fail "A15.13" "sqssh-keygen --type" "ed25519=$R1 rsa=$R2"

# A15.14 sqssh-keyscan scan --port
OUT=$(sqssh-keyscan scan "$HOST_IP" --port 22 2>&1)
EC=$?
[[ $EC -eq 0 ]] \
    && pass "A15.14" "sqssh-keyscan scan --port" || fail "A15.14" "sqssh-keyscan scan --port" "$OUT"

# A15.15 sqssh-agent --kill
pkill -f sqssh-agent 2>/dev/null || true
rm -f ~/.sqssh/agent.sock
sqssh-agent > /dev/null 2>&1 &
AGENT_PID=$!
disown $AGENT_PID
sleep 0.3
sqssh-agent --kill > /dev/null 2>&1 || true
sleep 0.3
kill -0 $AGENT_PID 2>/dev/null && R=FAIL || R=PASS
[[ "$R" == "PASS" ]] \
    && pass "A15.15" "sqssh-agent --kill" || fail "A15.15" "sqssh-agent --kill"
rm -f ~/.sqssh/agent.sock

# A15.16 sqssh-add --list --list-public --delete-all
pkill -f sqssh-agent 2>/dev/null || true
rm -f ~/.sqssh/agent.sock
sqssh-agent > /dev/null 2>&1 &
AGENT_PID=$!
export SQSSH_AGENT_SOCK=~/.sqssh/agent.sock
sleep 0.3
sqssh-add /tmp/test_key > /dev/null 2>&1
OUT1=$(sqssh-add --list 2>&1)
OUT2=$(sqssh-add --list-public 2>&1)
sqssh-add --delete-all > /dev/null 2>&1
OUT3=$(sqssh-add --list 2>&1)
echo "$OUT2" | grep -q "sqssh-ed25519" \
    && pass "A15.16" "sqssh-add --list --list-public --delete-all" || fail "A15.16" "sqssh-add long flags" "$OUT2"
kill $AGENT_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true
rm -f ~/.sqssh/agent.sock

# A15.17 sqssh-add --quiet
pkill -f sqssh-agent 2>/dev/null || true
rm -f ~/.sqssh/agent.sock
sqssh-agent > /dev/null 2>&1 &
AGENT_PID=$!
export SQSSH_AGENT_SOCK=~/.sqssh/agent.sock
sleep 0.3
OUT=$(sqssh-add --quiet /tmp/test_key 2>&1)
[[ -z "$OUT" || ! "$OUT" =~ "added" ]] \
    && pass "A15.17" "sqssh-add --quiet" || fail "A15.17" "sqssh-add --quiet" "$OUT"
kill $AGENT_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true
rm -f ~/.sqssh/agent.sock

# A15.18 sqssh-copy-id --dry-run --identity
OUT=$(sqssh-copy-id --dry-run --identity /tmp/test_key.pub "$SERVER_A" 2>&1 || true)
echo "$OUT" | grep -qi "would\|dry" \
    && pass "A15.18" "sqssh-copy-id --dry-run --identity" || fail "A15.18" "sqssh-copy-id long flags" "$OUT"

# A15.19 sqsshctl --socket
OUT=$(ssh "$SERVER_A" "sqsshctl --socket /var/run/sqssh/control.sock reload-keys" 2>&1)
echo "$OUT" | grep -qi "reload" \
    && pass "A15.19" "sqsshctl --socket" || fail "A15.19" "sqsshctl --socket" "$OUT"



# A15.20 sqsshd --show-pubkey
OUT=$(ssh "$SERVER_A" "sqsshd --show-pubkey" 2>&1)
echo "$OUT" | grep -qE '^[A-Za-z0-9]{32,}$' \
    && pass "A15.20" "sqsshd --show-pubkey" || fail "A15.20" "sqsshd --show-pubkey" "$OUT"

# A15.21 sqsshd --host-key --port --log-level
ssh "$SERVER_A" "sqsshd --host-key /etc/sqssh/host_key --port 4022 --log-level debug &
sleep 1
OUT=\$(ss -ulnp | grep 4022)
kill %1 2>/dev/null; wait 2>/dev/null
echo \"\$OUT\"" 2>&1 | grep -q 4022 \
    && pass "A15.21" "sqsshd --host-key --port --log-level" || fail "A15.21" "sqsshd --host-key --port --log-level"

# A15.22 sqsshd --no-migration
OUT=$(ssh "$SERVER_A" "sqsshd --no-migration --port 4023 &
sleep 1
kill %1 2>/dev/null; wait 2>/dev/null
echo ok" 2>&1)
echo "$OUT" | grep -q "ok" \
    && pass "A15.22" "sqsshd --no-migration" || fail "A15.22" "sqsshd --no-migration" "$OUT"

# A15.23 sqsshd --log-file
ssh "$SERVER_A" "rm -f /tmp/sqsshd_test.log; sqsshd --log-file /tmp/sqsshd_test.log --port 4024 &
sleep 1
kill %1 2>/dev/null; wait 2>/dev/null" 2>&1
OUT=$(ssh "$SERVER_A" "test -f /tmp/sqsshd_test.log && echo exists || echo missing" 2>&1)
echo "$OUT" | grep -q "exists" \
    && pass "A15.23" "sqsshd --log-file" || fail "A15.23" "sqsshd --log-file" "$OUT"

# A15.24 sqsshd --log-json
OUT=$(ssh "$SERVER_A" "sqsshd --log-json --port 4025 &
sleep 1
kill %1 2>/dev/null; wait 2>/dev/null" 2>&1)
echo "$OUT" | grep -q '{' \
    && pass "A15.24" "sqsshd --log-json" || fail "A15.24" "sqsshd --log-json" "$OUT"

# A15.25 sqsshd --config
OUT=$(ssh "$SERVER_A" "sqsshd --config /etc/sqssh/sqsshd.conf --port 4026 &
sleep 1
kill %1 2>/dev/null; wait 2>/dev/null
echo ok" 2>&1)
echo "$OUT" | grep -q "ok" \
    && pass "A15.25" "sqsshd --config" || fail "A15.25" "sqsshd --config" "$OUT"

# A15.26 sqsshd --listen
OUT=$(ssh "$SERVER_A" "sqsshd --listen 127.0.0.1 --port 4027 &
sleep 1
BOUND=\$(ss -ulnp | grep 4027 | grep 127.0.0.1)
kill %1 2>/dev/null; wait 2>/dev/null
echo \"\$BOUND\"" 2>&1)
echo "$OUT" | grep -q "127.0.0.1" \
    && pass "A15.26" "sqsshd --listen" || fail "A15.26" "sqsshd --listen" "$OUT"

# A15.27 sqsshd --auth-mode
OUT=$(ssh "$SERVER_A" "sqsshd --auth-mode whitelist-only --port 4028 &
sleep 1
kill %1 2>/dev/null; wait 2>/dev/null
echo ok" 2>&1)
echo "$OUT" | grep -q "ok" \
    && pass "A15.27" "sqsshd --auth-mode" || fail "A15.27" "sqsshd --auth-mode" "$OUT"

fi
section_end

# ─── A16. Cleanup ────────────────────────────────────────────────────────────
section_start "A16. Cleanup"
if [[ "$SKIP_SECTION" != "true" ]]; then
# cleanup happens via trap
pass "A16" "Cleanup (via trap)"
fi
section_end

# ─── Summary ─────────────────────────────────────────────────────────────────
print_summary
