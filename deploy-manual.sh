#!/bin/bash

# Manual deployment script for Obeeoma API
# Run this script directly on the server (not via SSH)

set -e

echo "=== Manual Obeeoma API Deployment ==="

# Navigate to project directory
cd ~/obeeoma_project/api

# Pull latest code
echo "Pulling latest code..."
git pull origin main

# Stop existing containers
echo "Stopping existing containers..."
docker-compose down

# Clean up Docker resources (optional - comment out if you want to keep cache)
echo "Cleaning up Docker resources..."
docker system prune -f

# Build and start containers
echo "Building and starting containers..."
docker-compose build --parallel
docker-compose up -d

# Wait for containers to start
echo "Waiting for containers to start..."
sleep 30

# Run Django commands
echo "Running Django migrations..."
docker-compose exec -T backend python manage.py migrate --noinput

echo "Collecting static files..."
docker-compose exec -T backend python manage.py collectstatic --noinput

# Health check
echo "Performing health check..."
for i in {1..10}; do
  if curl -f -s http://127.0.0.1:8000/api/v1/ > /dev/null; then
    echo "✅ Backend deployed successfully!"
    break
  else
    echo "⏳ Health check attempt $i/10 failed, retrying in 10 seconds..."
    sleep 10
  fi
  
  if [ $i -eq 10 ]; then
    echo "❌ Backend deployment failed after 10 attempts"
    echo "=== Container logs ==="
    docker-compose logs backend --tail 50
    echo "=== Container status ==="
    docker-compose ps
    exit 1
  fi
done

echo "=== Deployment complete! ==="
docker-compose ps
