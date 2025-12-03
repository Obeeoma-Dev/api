#!/bin/bash

# Script to set up SSH keys for GitHub Actions deployment

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  GitHub Actions SSH Key Setup for Digital Ocean             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check connection
echo " Testing connection to droplet..."
ssh -o ConnectTimeout=5 obeeoma@64.225.122.101 "echo ' Connected'" 2>/dev/null

if [ $? -ne 0 ]; then
    echo " Cannot connect to droplet"
    echo ""
    echo "Make sure you can SSH:"
    echo "  ssh obeeoma@64.225.122.101"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Generating SSH key on droplet..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Generate SSH key on droplet
ssh obeeoma@64.225.122.101 << 'ENDSSH'
# Check if key already exists
if [ -f ~/.ssh/github_deploy ]; then
    echo " SSH key already exists. Using existing key."
else
    echo " Generating new SSH key..."
    ssh-keygen -t ed25519 -C "github-actions" -f ~/.ssh/github_deploy -N ""
    echo "SSH key generated"
fi

# Add to authorized_keys if not already there
if ! grep -q "github-actions" ~/.ssh/authorized_keys 2>/dev/null; then
    cat ~/.ssh/github_deploy.pub >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    echo " Public key added to authorized_keys"
else
    echo " Public key already in authorized_keys"
fi
ENDSSH

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " GitHub Secrets Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Add these secrets to your GitHub repository:"
echo ""
echo "1. Go to: GitHub → Settings → Secrets and variables → Actions"
echo "2. Click 'New repository secret'"
echo "3. Add these three secrets:"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Secret 1: DROPLET_HOST"
echo "Value: 64.225.122.101"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Secret 2: DROPLET_USERNAME"
echo "Value: obeeoma"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Secret 3: DROPLET_SSH_KEY"
echo "Value: (Copy the ENTIRE private key below, including BEGIN and END lines)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Display the private key
ssh obeeoma@64.225.122.101 "cat ~/.ssh/github_deploy"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo " Setup complete!"
echo ""
echo "Next steps:"
echo "1. Copy the private key above"
echo "2. Add all three secrets to GitHub"
echo "3. Push to main branch to trigger deployment"
echo ""
echo "Test deployment:"
echo "  git add ."
echo "  git commit -m 'Test deployment'"
echo "  git push origin main"
echo ""
