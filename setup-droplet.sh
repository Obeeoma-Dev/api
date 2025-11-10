#!/bin/bash

# DigitalOcean Droplet Setup Script
# Run this script on your droplet after connecting via SSH

set -e

echo "🚀 Starting DigitalOcean Droplet Setup..."

# Update system
echo "📦 Updating system packages..."
apt update && apt upgrade -y

# Create deploy user
echo "👤 Creating deploy user..."
if ! id -u deploy > /dev/null 2>&1; then
    adduser --disabled-password --gecos "" deploy
    usermod -aG sudo deploy
    echo "deploy ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
fi

# Install Docker
echo "🐳 Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
fi

# Add deploy user to docker group
usermod -aG docker deploy

# Install Docker Compose
echo "📦 Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

# Set up firewall
echo "🔥 Configuring firewall..."
ufw --force enable
ufw allow OpenSSH
ufw allow 80
ufw allow 443
ufw allow 8000

# Generate SSH key for deploy user
echo "🔑 Generating SSH key for deploy user..."
sudo -u deploy bash << 'EOF'
cd ~
if [ ! -f ~/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519 -C "github-actions" -f ~/.ssh/id_ed25519 -N ""
    cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
fi
EOF

# Display SSH private key
echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Copy the SSH private key below and add it to GitHub Secrets as DROPLET_SSH_KEY"
echo "2. Clone your repository to /home/deploy/api"
echo "3. Create .env file with your environment variables"
echo "4. Run: docker-compose up -d"
echo ""
echo "🔑 SSH Private Key (copy this):"
echo "================================"
sudo -u deploy cat /home/deploy/.ssh/id_ed25519
echo "================================"
echo ""
echo "🌐 Your droplet IP: $(curl -s ifconfig.me)"
echo ""
