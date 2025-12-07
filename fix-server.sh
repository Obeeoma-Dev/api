#!/bin/bash

echo "🔧 Fixing Digital Ocean Server..."
echo ""

ssh obeeoma@64.225.122.101 << 'ENDSSH'
cd ~/obeeoma_project/api

echo "1. Pulling latest code..."
git pull origin main

echo ""
echo "2. Stopping containers..."
docker-compose down

echo ""
echo "3. Rebuilding containers (this may take a few minutes)..."
docker-compose build --no-cache

echo ""
echo "4. Starting containers..."
docker-compose up -d

echo ""
echo "5. Waiting for containers to start..."
sleep 10

echo ""
echo "6. Checking container status..."
docker-compose ps

echo ""
echo "7. Checking for errors in logs..."
docker-compose logs backend --tail=30

echo ""
echo "8. Testing API..."
curl -s http://localhost:8000/api/v1/ | head -20

echo ""
echo "✅ Done! Check if the API is responding above."
ENDSSH

echo ""
echo "Now test your API at: http://64.225.122.101:8000/api/v1/api/docs/"
