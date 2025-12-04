#!/bin/bash

# Digital Ocean Droplet Setup Script for Docker Deployment
# Run this on your droplet as obeeoma user

set -e

echo "🚀 Starting Digital Ocean Droplet Setup..."

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Update system
echo -e "${BLUE}📦 Updating system packages...${NC}"
sudo apt update && sudo apt upgrade -y

# Install Docker
echo -e "${BLUE}🐳 Installing Docker...${NC}"
if command -v docker &> /dev/null; then
    echo "Docker already installed"
else
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    rm get-docker.sh
fi

# Add current user to docker group
sudo usermod -aG docker $USER

# Install Docker Compose
echo -e "${BLUE}🔧 Installing Docker Compose...${NC}"
if command -v docker-compose &> /dev/null; then
    echo "Docker Compose already installed"
else
    sudo curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

# Configure firewall
echo -e "${BLUE}🔥 Configuring firewall...${NC}"
sudo ufw --force enable
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8000/tcp

# Generate SSH key for GitHub Actions
echo -e "${BLUE}🔑 Generating SSH key for GitHub Actions...${NC}"
if [ ! -f ~/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519 -C "github-actions" -f ~/.ssh/id_ed25519 -N ""
    cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    chmod 700 ~/.ssh
fi

# Display SSH private key
echo -e "${GREEN}✅ Setup complete!${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}📋 Next Steps:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Copy this SSH private key to GitHub Secrets as DROPLET_SSH_KEY:"
echo ""
cat ~/.ssh/id_ed25519
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "2. Add these GitHub Secrets:"
echo "   - DROPLET_HOST: $(curl -s ifconfig.me)"
echo "   - DROPLET_USERNAME: obeeoma"
echo "   - DROPLET_SSH_KEY: (paste the key above)"
echo ""
echo "3. Log out and back in for Docker group changes:"
echo "   exit"
echo "   ssh obeeoma@64.225.122.101"
echo ""
echo "4. Clone your repo:"
echo "   git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git api"
echo "   cd api"
echo ""
echo "4. Create .env file with your production settings"
echo ""
echo "5. Start Docker containers:"
echo "   docker-compose up -d"
echo ""
echo -e "${GREEN}🎉 Your droplet is ready for deployment!${NC}"
