#!/bin/bash
# Fix deployment issues on Digital Ocean droplet

echo "🔧 Fixing deployment issues..."

# Step 1: Fix migration issue - fake the problematic migration
echo "📋 Step 1: Fixing migration issue..."
docker-compose exec -T backend python manage.py migrate obeeomaapp 0021 --fake
docker-compose exec -T backend python manage.py migrate --fake-initial

# Step 2: Check if tables exist
echo "📊 Step 2: Checking database tables..."
docker-compose exec -T backend python manage.py dbshell << 'EOF'
\dt obeeomaapp_*
\q
EOF

# Step 3: Try migrations again
echo "🔄 Step 3: Running migrations..."
docker-compose exec -T backend python manage.py migrate

# Step 4: Restart containers
echo "🔄 Step 4: Restarting containers..."
docker-compose restart

# Step 5: Check status
echo "✅ Step 5: Checking container status..."
docker-compose ps

echo "✅ Done! Check if the API is working now."
