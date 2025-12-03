#!/bin/bash

# Script to copy Google OAuth credentials from local .env to droplet

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Copy Google OAuth Credentials to Digital Ocean Droplet     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if .env.template exists (created by get_oauth2_token.py)
if [ -f ".env.template" ]; then
    echo "✅ Found .env.template with OAuth credentials"
    echo ""
    echo "Credentials to be copied:"
    cat .env.template
    echo ""
else
    echo "❌ .env.template not found!"
    echo ""
    echo "Please run first:"
    echo "  python get_oauth2_token.py"
    echo ""
    exit 1
fi

# Extract credentials
GOOGLE_CLIENT_ID=$(grep GOOGLE_CLIENT_ID .env.template | cut -d'=' -f2)
GOOGLE_CLIENT_SECRET=$(grep GOOGLE_CLIENT_SECRET .env.template | cut -d'=' -f2)
GOOGLE_REFRESH_TOKEN=$(grep GOOGLE_REFRESH_TOKEN .env.template | cut -d'=' -f2)
EMAIL_HOST_USER=$(grep EMAIL_HOST_USER .env.template | cut -d'=' -f2)

if [ -z "$GOOGLE_CLIENT_ID" ] || [ -z "$GOOGLE_CLIENT_SECRET" ] || [ -z "$GOOGLE_REFRESH_TOKEN" ]; then
    echo "❌ Could not extract credentials from .env.template"
    exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Connecting to droplet..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Test connection
ssh -o ConnectTimeout=5 obeeoma@64.225.122.101 "echo '✅ Connected'" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "❌ Cannot connect to droplet"
    echo ""
    echo "Make sure you can SSH:"
    echo "  ssh obeeoma@64.225.122.101"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Updating .env on droplet..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Update .env on droplet
ssh obeeoma@64.225.122.101 << ENDSSH
cd ~/api

# Backup current .env
cp .env .env.backup.\$(date +%Y%m%d_%H%M%S)

# Remove old Google OAuth entries if they exist
sed -i '/GOOGLE_CLIENT_ID/d' .env
sed -i '/GOOGLE_CLIENT_SECRET/d' .env
sed -i '/GOOGLE_REFRESH_TOKEN/d' .env

# Add new credentials
echo "" >> .env
echo "# Google OAuth for Gmail API (Added $(date))" >> .env
echo "GOOGLE_CLIENT_ID=$GOOGLE_CLIENT_ID" >> .env
echo "GOOGLE_CLIENT_SECRET=$GOOGLE_CLIENT_SECRET" >> .env
echo "GOOGLE_REFRESH_TOKEN=$GOOGLE_REFRESH_TOKEN" >> .env

# Update email settings if not present
if ! grep -q "EMAIL_HOST_USER" .env; then
    echo "EMAIL_HOST_USER=$EMAIL_HOST_USER" >> .env
fi
if ! grep -q "DEFAULT_FROM_EMAIL" .env; then
    echo "DEFAULT_FROM_EMAIL=$EMAIL_HOST_USER" >> .env
fi

echo "✅ Credentials added to .env"
echo ""
echo "Verifying..."
grep GOOGLE .env | sed 's/=.*/=***HIDDEN***/'

ENDSSH

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Restarting Docker containers..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

ssh obeeoma@64.225.122.101 << ENDSSH
cd ~/api
docker-compose restart
echo ""
echo "✅ Containers restarted"
ENDSSH

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Setup Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next steps:"
echo "1. Send a test invitation from your app"
echo "2. Check logs:"
echo "   ssh obeeoma@64.225.122.101 'cd ~/api && docker-compose logs backend | grep -i email'"
echo ""
echo "You should see: 'Email sent via Gmail API to ...'"
echo ""
