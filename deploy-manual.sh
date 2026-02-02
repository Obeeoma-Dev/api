#!/bin/bash
# Manual deployment script for Digital Ocean

echo "🚀 Starting manual deployment to Digital Ocean..."

# SSH into droplet and deploy
ssh root@YOUR_DROPLET_IP << 'ENDSSH'
  cd ~/obeeoma_project/api
  
  echo "📥 Pulling latest code..."
  git pull origin main
  
  echo "🐳 Rebuilding Docker containers..."
  docker-compose down
  docker-compose build
  docker-compose up -d
  
  echo "🔄 Running migrations..."
  docker-compose exec -T backend python manage.py migrate --noinput
  
  echo "📦 Collecting static files..."
  docker-compose exec -T backend python manage.py collectstatic --noinput
  
  echo "✅ Deployment complete!"
  docker-compose ps
ENDSSH

echo "✅ Manual deployment finished!"
