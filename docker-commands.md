# 🐳 Docker Commands Reference

Quick reference for managing your Dockerized Django application.

## Container Management

### Start/Stop Services
```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Restart all services
docker-compose restart

# Restart specific service
docker-compose restart backend
docker-compose restart nginx
```

### View Status
```bash
# List running containers
docker ps

# List all containers (including stopped)
docker ps -a

# View resource usage
docker stats
```

### Logs
```bash
# View all logs
docker-compose logs

# Follow logs (real-time)
docker-compose logs -f

# View specific service logs
docker-compose logs backend
docker-compose logs nginx

# Last 100 lines
docker-compose logs --tail=100 backend

# Logs with timestamps
docker-compose logs -t backend
```

## Building & Updating

### Build Containers
```bash
# Build all services
docker-compose build

# Build without cache
docker-compose build --no-cache

# Build specific service
docker-compose build backend
```

### Update & Rebuild
```bash
# Pull latest code and rebuild
git pull origin main
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Django Management Commands

### Migrations
```bash
# Run migrations
docker-compose exec backend python manage.py migrate

# Create migrations
docker-compose exec backend python manage.py makemigrations

# Show migrations
docker-compose exec backend python manage.py showmigrations

# Migrate specific app
docker-compose exec backend python manage.py migrate obeeomaapp
```

### User Management
```bash
# Create superuser
docker-compose exec backend python manage.py createsuperuser

# Change user password
docker-compose exec backend python manage.py changepassword username
```

### Static Files
```bash
# Collect static files
docker-compose exec backend python manage.py collectstatic --noinput

# Clear static files
docker-compose exec backend python manage.py collectstatic --clear --noinput
```

### Database
```bash
# Django shell
docker-compose exec backend python manage.py shell

# Database shell
docker-compose exec backend python manage.py dbshell

# Flush database (careful!)
docker-compose exec backend python manage.py flush
```

### Testing
```bash
# Run all tests
docker-compose exec backend python manage.py test

# Run specific test
docker-compose exec backend python manage.py test obeeomaapp.tests.test_models

# Run with pytest
docker-compose exec backend pytest

# Run with coverage
docker-compose exec backend pytest --cov
```

## Debugging

### Access Container Shell
```bash
# Access backend container
docker-compose exec backend bash

# Access nginx container
docker-compose exec nginx sh

# Access as root
docker-compose exec -u root backend bash
```

### Inspect Container
```bash
# View container details
docker inspect django_backend

# View container processes
docker top django_backend

# View container logs
docker logs django_backend
```

### Check Configuration
```bash
# Check Django configuration
docker-compose exec backend python manage.py check

# Check deployment readiness
docker-compose exec backend python manage.py check --deploy

# Show Django settings
docker-compose exec backend python manage.py diffsettings
```

## Cleanup

### Remove Containers
```bash
# Stop and remove containers
docker-compose down

# Remove containers and volumes
docker-compose down -v

# Remove containers, volumes, and images
docker-compose down -v --rmi all
```

### Clean Up System
```bash
# Remove unused containers, networks, images
docker system prune

# Remove everything (careful!)
docker system prune -a

# Remove unused volumes
docker volume prune

# Remove unused images
docker image prune
```

## Backup & Restore

### Database Backup
```bash
# Backup database (if using PostgreSQL in Docker)
docker-compose exec backend python manage.py dumpdata > backup.json

# Backup specific app
docker-compose exec backend python manage.py dumpdata obeeomaapp > obeeomaapp_backup.json

# Backup with indentation
docker-compose exec backend python manage.py dumpdata --indent 2 > backup.json
```

### Database Restore
```bash
# Restore from backup
docker-compose exec backend python manage.py loaddata backup.json

# Restore specific app
docker-compose exec backend python manage.py loaddata obeeomaapp_backup.json
```

### Media Files Backup
```bash
# Backup media files
tar -czf media_backup.tar.gz media/

# Restore media files
tar -xzf media_backup.tar.gz
```

## Monitoring

### Resource Usage
```bash
# View resource usage
docker stats

# View disk usage
docker system df

# View detailed disk usage
docker system df -v
```

### Health Checks
```bash
# Check if backend is responding
curl http://localhost:8000/

# Check nginx
curl http://localhost:80/

# Check from inside container
docker-compose exec backend curl http://localhost:8000/
```

## Network

### Network Commands
```bash
# List networks
docker network ls

# Inspect network
docker network inspect api_default

# View container IPs
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' django_backend
```

## Environment Variables

### View Environment
```bash
# View all environment variables
docker-compose exec backend env

# View specific variable
docker-compose exec backend printenv DATABASE_URL

# Run with custom env
docker-compose exec -e DEBUG=True backend python manage.py runserver
```

## Quick Troubleshooting

### Container Won't Start
```bash
# Check logs
docker-compose logs backend

# Check if port is in use
sudo lsof -i :8000

# Remove and rebuild
docker-compose down
docker-compose up -d --build
```

### Database Connection Issues
```bash
# Check database connection
docker-compose exec backend python manage.py dbshell

# Check environment variables
docker-compose exec backend env | grep PG

# Test connection
docker-compose exec backend python manage.py check --database default
```

### Static Files Not Loading
```bash
# Recollect static files
docker-compose exec backend python manage.py collectstatic --clear --noinput

# Check nginx configuration
docker-compose exec nginx nginx -t

# Restart nginx
docker-compose restart nginx
```

### Permission Issues
```bash
# Fix permissions
docker-compose exec -u root backend chown -R www-data:www-data /app

# Check file permissions
docker-compose exec backend ls -la
```

## Useful Aliases

Add these to your `~/.bashrc` or `~/.zshrc`:

```bash
# Docker Compose shortcuts
alias dc='docker-compose'
alias dcup='docker-compose up -d'
alias dcdown='docker-compose down'
alias dclogs='docker-compose logs -f'
alias dcrestart='docker-compose restart'
alias dcbuild='docker-compose build --no-cache'

# Django shortcuts
alias djmigrate='docker-compose exec backend python manage.py migrate'
alias djshell='docker-compose exec backend python manage.py shell'
alias djtest='docker-compose exec backend python manage.py test'
alias djcollect='docker-compose exec backend python manage.py collectstatic --noinput'
```

## Emergency Commands

### Complete Reset
```bash
# Stop everything
docker-compose down -v

# Remove all containers
docker rm -f $(docker ps -aq)

# Remove all images
docker rmi -f $(docker images -q)

# Clean system
docker system prune -a --volumes

# Rebuild from scratch
docker-compose up -d --build
```

### Quick Restart
```bash
# One-liner to restart everything
docker-compose down && docker-compose up -d --build && docker-compose logs -f
```
