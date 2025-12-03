#!/bin/bash

# Script to check account setup errors

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Checking Complete Account Setup Error                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "Are you testing locally or on Digital Ocean?"
echo "1) Local (localhost:8000)"
echo "2) Digital Ocean (64.225.122.101)"
read -p "Enter choice (1 or 2): " choice

if [ "$choice" = "1" ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Checking LOCAL Django logs..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    if [ -f "django.log" ]; then
        echo "Last 50 lines of django.log:"
        tail -50 django.log | grep -i -E "(error|exception|traceback|complete.*account)" --color=always
    else
        echo "django.log not found. Check your Django logs."
    fi
    
elif [ "$choice" = "2" ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Checking DIGITAL OCEAN Docker logs..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    ssh obeeoma@64.225.122.101 << 'ENDSSH'
cd ~/obeeoma_project/api

echo "Last 100 lines of backend logs (filtering for errors):"
echo ""
docker-compose logs backend --tail=100 | grep -i -E "(error|exception|traceback|complete.*account|500)" --color=always

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Recent API requests:"
echo ""
docker-compose logs backend --tail=50 | grep -i "POST.*complete" --color=always
ENDSSH

else
    echo "Invalid choice"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Common Issues:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Missing 'email' field in request"
echo "   Fix: Make sure you're sending: {email, username, password, confirm_password}"
echo ""
echo "2. First login not completed"
echo "   Fix: Use temporary credentials first, then complete account setup"
echo ""
echo "3. Invitation expired or already used"
echo "   Fix: Request a new invitation"
echo ""
echo "4. Database connection issue"
echo "   Fix: Check DATABASE_URL in .env"
echo ""
