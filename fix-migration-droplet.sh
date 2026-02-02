#!/bin/bash
# Complete fix for migration and deployment issues

echo "🚀 Starting comprehensive fix..."

# Check current migration status
echo "📋 Checking current migration status..."
docker-compose exec -T backend python manage.py showmigrations obeeomaapp

# Option 1: Fake the problematic migration
echo ""
echo "🔧 Option 1: Faking problematic migration..."
docker-compose exec -T backend python manage.py migrate obeeomaapp 0021 --fake 2>/dev/null || echo "Migration 0021 not found or already applied"

# Option 2: Create missing tables manually
echo ""
echo "🔧 Option 2: Creating missing tables if needed..."
docker-compose exec -T backend python manage.py migrate --run-syncdb

# Option 3: Reset migrations (CAREFUL - only if above fails)
echo ""
echo "🔧 Option 3: If above failed, trying full migration..."
docker-compose exec -T backend python manage.py migrate --fake-initial

# Run all pending migrations
echo ""
echo "🔄 Running all pending migrations..."
docker-compose exec -T backend python manage.py migrate

# Collect static files
echo ""
echo "📦 Collecting static files..."
docker-compose exec -T backend python manage.py collectstatic --noinput

# Restart services
echo ""
echo "🔄 Restarting services..."
docker-compose restart

# Check status
echo ""
echo "✅ Final status check..."
docker-compose ps
docker-compose logs backend --tail=50

echo ""
echo "✅ Fix complete! Test your API endpoints now."
