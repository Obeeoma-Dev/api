#!/bin/bash

# Script to check Google OAuth configuration on Digital Ocean droplet

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Checking Google OAuth Email Configuration on Droplet       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if we can connect
echo "📡 Connecting to droplet..."
ssh -o ConnectTimeout=5 obeeoma@64.225.122.101 "echo '✅ Connected successfully'" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "❌ Cannot connect to droplet. Check your SSH connection."
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Checking Google OAuth Environment Variables"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

ssh obeeoma@64.225.122.101 << 'ENDSSH'
cd ~/api

if [ ! -f .env ]; then
    echo "❌ .env file not found!"
    exit 1
fi

echo ""
echo "GOOGLE_CLIENT_ID:"
if grep -q "GOOGLE_CLIENT_ID" .env; then
    VALUE=$(grep GOOGLE_CLIENT_ID .env | cut -d'=' -f2)
    if [ -z "$VALUE" ] || [ "$VALUE" = "your-client-id" ]; then
        echo "  ❌ Not configured (empty or default value)"
    else
        echo "  ✅ Configured: ${VALUE:0:30}..."
    fi
else
    echo "  ❌ Missing from .env"
fi

echo ""
echo "GOOGLE_CLIENT_SECRET:"
if grep -q "GOOGLE_CLIENT_SECRET" .env; then
    VALUE=$(grep GOOGLE_CLIENT_SECRET .env | cut -d'=' -f2)
    if [ -z "$VALUE" ] || [ "$VALUE" = "your-client-secret" ]; then
        echo "  ❌ Not configured (empty or default value)"
    else
        echo "  ✅ Configured: ${VALUE:0:20}..."
    fi
else
    echo "  ❌ Missing from .env"
fi

echo ""
echo "GOOGLE_REFRESH_TOKEN:"
if grep -q "GOOGLE_REFRESH_TOKEN" .env; then
    VALUE=$(grep GOOGLE_REFRESH_TOKEN .env | cut -d'=' -f2)
    if [ -z "$VALUE" ] || [ "$VALUE" = "your-refresh-token" ]; then
        echo "  ❌ Not configured (empty or default value)"
    else
        echo "  ✅ Configured: ${VALUE:0:20}..."
    fi
else
    echo "  ❌ Missing from .env"
fi

echo ""
echo "EMAIL_HOST_USER:"
if grep -q "EMAIL_HOST_USER" .env; then
    VALUE=$(grep EMAIL_HOST_USER .env | cut -d'=' -f2)
    echo "  ✅ $VALUE"
else
    echo "  ❌ Missing from .env"
fi

ENDSSH

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. Checking Docker Containers"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

ssh obeeoma@64.225.122.101 << 'ENDSSH'
cd ~/api

if docker ps | grep -q backend; then
    echo "✅ Backend container is running"
    docker ps | grep backend | awk '{print "   Container:", $NF, "Status:", $(NF-1)}'
else
    echo "❌ Backend container is not running"
fi

ENDSSH

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. Checking Recent Email Logs"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

ssh obeeoma@64.225.122.101 << 'ENDSSH'
cd ~/api

echo ""
echo "Last 10 email-related log entries:"
echo ""
docker-compose logs backend --tail=200 2>/dev/null | grep -i -E "(email|gmail|invitation|smtp)" | tail -10

if [ $? -ne 0 ]; then
    echo "No email-related logs found or container not running"
fi

ENDSSH

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Summary & Next Steps"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "If you see ❌ marks above, you need to:"
echo ""
echo "1. Generate OAuth tokens locally:"
echo "   python get_oauth2_token.py"
echo ""
echo "2. Copy credentials to droplet:"
echo "   ssh obeeoma@64.225.122.101"
echo "   cd ~/api"
echo "   nano .env"
echo "   (Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN)"
echo ""
echo "3. Restart containers:"
echo "   docker-compose restart"
echo ""
echo "4. Test by sending an invitation"
echo ""
echo "📖 Full guide: See SETUP_GOOGLE_OAUTH_EMAIL.md"
echo ""
