#!/bin/sh
set -e

REPO="wave-cl/sqssh"
INSTALL_DIR="${SQSSH_INSTALL_DIR:-}"
SERVER_MODE=false

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --server) SERVER_MODE=true ;;
    esac
done

info() { printf "  \033[1m%s\033[0m\n" "$1"; }
err()  { printf "  \033[31merror:\033[0m %s\n" "$1" >&2; exit 1; }

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  OS_NAME="linux" ;;
    Darwin) OS_NAME="darwin" ;;
    *)      err "unsupported OS: $OS" ;;
esac

case "$ARCH" in
    x86_64|amd64)   TARGET="x86_64-linux-gnu" ;;
    aarch64|arm64)   TARGET="aarch64-linux-gnu" ;;
    *)               err "unsupported architecture: $ARCH" ;;
esac

# Fix target for macOS
if [ "$OS_NAME" = "darwin" ]; then
    case "$ARCH" in
        x86_64|amd64)  TARGET="x86_64-apple-darwin" ;;
        aarch64|arm64) TARGET="aarch64-apple-darwin" ;;
    esac
fi

# Determine install directory
if [ -n "$INSTALL_DIR" ]; then
    BIN_DIR="$INSTALL_DIR"
elif [ "$(id -u)" -eq 0 ]; then
    BIN_DIR="/usr/local/bin"
else
    BIN_DIR="$HOME/.local/bin"
fi

# Detect download tool
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO- "$1"; }
else
    err "curl or wget required"
fi

# Get latest release tag
info "Fetching latest release..."
LATEST=$(fetch "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
[ -z "$LATEST" ] && err "could not determine latest version"
info "Latest version: $LATEST"

# Download and extract
URL="https://github.com/$REPO/releases/download/$LATEST/sqssh-${LATEST}-${TARGET}.tar.gz"
info "Downloading sqssh $LATEST for $TARGET..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

fetch "$URL" > "$TMPDIR/sqssh.tar.gz" || err "download failed — no release for $TARGET?"

info "Installing to $BIN_DIR..."
mkdir -p "$BIN_DIR"
tar -xzf "$TMPDIR/sqssh.tar.gz" -C "$BIN_DIR"

# Verify
if ! "$BIN_DIR/sqssh" --version >/dev/null 2>&1; then
    err "installation failed — sqssh not executable"
fi

VERSION=$("$BIN_DIR/sqssh" --version 2>&1 || echo "unknown")
info "Installed: $VERSION"

# PATH setup for non-root installs
if [ "$BIN_DIR" = "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;  # already in PATH
        *)
            SHELL_NAME=$(basename "$SHELL" 2>/dev/null || echo "unknown")
            case "$SHELL_NAME" in
                bash)
                    RC="$HOME/.bashrc"
                    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC"
                    info "Added ~/.local/bin to PATH in $RC"
                    ;;
                zsh)
                    RC="$HOME/.zshrc"
                    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC"
                    info "Added ~/.local/bin to PATH in $RC"
                    ;;
                fish)
                    RC="$HOME/.config/fish/config.fish"
                    mkdir -p "$(dirname "$RC")"
                    echo 'fish_add_path ~/.local/bin' >> "$RC"
                    info "Added ~/.local/bin to PATH in $RC"
                    ;;
                *)
                    info "Add $BIN_DIR to your PATH"
                    ;;
            esac
            info "Restart your shell or run: export PATH=\"$BIN_DIR:\$PATH\""
            ;;
    esac
fi

# Server setup
if [ "$SERVER_MODE" = true ]; then
    info "Setting up sqsshd server..."

    # Must be root
    if [ "$(id -u)" -ne 0 ]; then
        err "--server requires root"
    fi

    # Must be Linux
    if [ "$OS_NAME" != "linux" ]; then
        err "--server is only supported on Linux"
    fi

    # Create /etc/sqssh with correct permissions
    mkdir -p /etc/sqssh
    chmod 755 /etc/sqssh

    # Create ~/.sqssh directory for root
    mkdir -p "$HOME/.sqssh"
    chmod 700 "$HOME/.sqssh"
    if [ ! -f "$HOME/.sqssh/authorized_keys" ]; then
        touch "$HOME/.sqssh/authorized_keys"
        chmod 600 "$HOME/.sqssh/authorized_keys"
    fi

    # Generate host key if not exists
    if [ -f /etc/sqssh/host_key ]; then
        info "Host key already exists, skipping generation"
    else
        info "Generating host key..."
        echo "" | "$BIN_DIR/sqssh-keygen" -f /etc/sqssh/host_key -C "host-key" > /dev/null 2>&1
        chmod 600 /etc/sqssh/host_key
        chmod 644 /etc/sqssh/host_key.pub
        info "Host key generated"
    fi

    # Write config if not exists
    if [ -f /etc/sqssh/sqsshd.conf ]; then
        info "Config already exists, skipping"
    else
        info "Writing default config to /etc/sqssh/sqsshd.conf..."
        cat > /etc/sqssh/sqsshd.conf << 'CONF'
# sqsshd configuration
# See README for all directives

Port 22
HostKey /etc/sqssh/host_key
AuthMode whitelist+user
AuthorizedKeysFile .sqssh/authorized_keys
MaxSessions 64
MaxAuthTries 6
ControlSocket /var/run/sqssh/control.sock
ConnectionMigration yes
PrintMotd yes
PrintLastLog yes
# Banner /etc/sqssh/banner
# AllowUsers
# DenyUsers
CONF
        chmod 644 /etc/sqssh/sqsshd.conf
    fi

    # Install systemd service (always overwrite for upgrades)
    if command -v systemctl >/dev/null 2>&1; then
        info "Installing systemd service..."
        cat > /etc/systemd/system/sqsshd.service << 'SVC'
[Unit]
Description=sqssh server daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sqsshd --config /etc/sqssh/sqsshd.conf
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure
RestartSec=2
RuntimeDirectory=sqssh

[Install]
WantedBy=multi-user.target
SVC
        chmod 644 /etc/systemd/system/sqsshd.service
        systemctl daemon-reload
        systemctl enable sqsshd

        if systemctl is-active sqsshd >/dev/null 2>&1; then
            info "Restarting sqsshd..."
            systemctl restart sqsshd
        else
            info "Starting sqsshd..."
            systemctl start sqsshd
        fi

        # Verify
        sleep 1
        if systemctl is-active sqsshd >/dev/null 2>&1; then
            info "sqsshd is running"
        else
            err "sqsshd failed to start — check: journalctl -u sqsshd"
        fi
    else
        info "systemd not found — skipping service installation"
        info "Start manually: sqsshd --config /etc/sqssh/sqsshd.conf"
    fi

    # Print server pubkey
    PUBKEY=$(cat /etc/sqssh/host_key.pub 2>/dev/null | awk '{print $2}')
    printf "\n"
    info "Server public key:"
    printf "  %s\n" "$PUBKEY"
    printf "\n"
    # Prefer public IP for remote access instructions, fall back to hostname
    HOSTNAME="$(curl -4 -fsSL -m 3 https://ifconfig.me 2>/dev/null || hostname -f 2>/dev/null || hostname)"
    info "Next steps:"
    printf "  1. Add user keys:    ssh root@%s 'echo \"sqssh-ed25519 <pubkey> <comment>\" >> ~/.sqssh/authorized_keys'\n" "$HOSTNAME"
    printf "  2. Reload whitelist: ssh root@%s 'sqsshctl reload-keys --all'\n" "$HOSTNAME"
    printf "  3. On client:        sqssh-keyscan add %s %s\n" "$HOSTNAME" "$PUBKEY"
    printf "\n"
    info "Connect:"
    printf "  sqssh root@%s\n" "$HOSTNAME"
    printf "\n"
else
    printf "\n"
    info "Getting started:"
    printf "  Generate a key:        sqssh-keygen\n"
    printf "  With a passphrase:     sqssh-keygen --new-passphrase \"your passphrase\"\n"
    printf "  Show your public key:  sqssh-keygen --print-public\n"
    printf "\n"
    info "Server setup (via SSH):"
    printf "  Install server:         ssh root@host 'curl -fsSL https://raw.githubusercontent.com/wave-cl/sqssh/main/install.sh | sh -s -- --server'\n"
    printf "  Add your key:           ssh root@host 'echo \"sqssh-ed25519 <your-pubkey> <comment>\" >> ~/.sqssh/authorized_keys'\n"
    printf "  Reload whitelist:       ssh root@host 'sqsshctl reload-keys --all'\n"
    printf "  Get server pubkey:      ssh root@host 'sqsshd --show-pubkey'\n"
    printf "\n"
    info "Connecting to a server:"
    printf "  Add the server's pubkey:  sqssh-keyscan add <host> <server-pubkey>\n"
    printf "  Connect:                  sqssh user@host\n"
    printf "\n"
fi
