#!/usr/bin/env bash
set -e

echo "========================================================================"
echo "🛡️  scafonix Vault — Amazon Lightsail 1-Click Setup Script"
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

# 3. Build release binary
echo "Building scafonix-server in release mode..."
cargo build --release -p scafonix-server

# 4. Install systemd service
echo "Configuring systemd service..."
sudo cp deploy/scafonix-vault.service /etc/systemd/system/scafonix-vault.service
sudo systemctl daemon-reload
sudo systemctl enable scafonix-vault.service
sudo systemctl restart scafonix-vault.service

# 5. Configure Nginx Reverse Proxy (Port 80 -> Port 3000)
echo "Configuring Nginx Reverse Proxy..."
sudo tee /etc/nginx/sites-available/scafonix-vault > /dev/null << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/scafonix-vault /etc/nginx/sites-enabled/default
sudo systemctl restart nginx

# 6. Configure UFW Firewall
sudo ufw allow 22/tcp || true
sudo ufw allow 80/tcp || true
sudo ufw allow 443/tcp || true
sudo ufw allow 3000/tcp || true

echo "========================================================================"
echo "🎉 scafonix Vault 2nd Inspector is NOW LIVE on your Lightsail Instance!"
echo "   Test with: curl http://localhost/health"
echo "========================================================================"
