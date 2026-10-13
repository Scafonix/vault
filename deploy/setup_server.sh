#!/usr/bin/env bash
set -e

echo "========================================================================"
echo "scafonix Vault — Dedicated Server Setup Script"
echo "========================================================================"

# 1. Update OS and install dependencies
sudo apt-get update -y
sudo apt-get install -y build-essential pkg-config libssl-dev git curl nginx ufw

# 2. Install Rust toolchain (if not already installed)
if ! command -v rustc &> /dev/null; then
    echo "Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
fi

# 3. Create dedicated system user and directories
sudo useradd -r -s /bin/false vault || true
sudo mkdir -p /var/lib/scafonix-vault
sudo chown -R vault:vault /var/lib/scafonix-vault
sudo chmod 700 /var/lib/scafonix-vault

sudo mkdir -p /opt/scafonix-vault
cargo build --release -p scafonix-server
sudo cp target/release/scafonix-server /opt/scafonix-vault/
sudo chown -R vault:vault /opt/scafonix-vault

# 4. Install systemd service
echo "Configuring systemd service..."
sudo cp deploy/scafonix-vault.service /etc/systemd/system/scafonix-vault.service
sudo systemctl daemon-reload
sudo systemctl enable scafonix-vault.service
sudo systemctl restart scafonix-vault.service

echo "========================================================================"
echo "scafonix Vault 2nd Inspector is running!"
echo "Test with: curl http://localhost:3000/health"
echo "========================================================================"
