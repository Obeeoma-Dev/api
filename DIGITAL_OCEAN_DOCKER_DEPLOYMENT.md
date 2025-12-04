# Digital Ocean Docker Deployment Guide

Complete guide to deploy your Django API to Digital Ocean with automatic Docker deployments.

## 🎯 Overview

Your API will be deployed at: **http://64.225.122.101:8000/api/v1/api/docs/**

This guide covers:
- Docker setup on Digital Ocean droplet
- Automatic deployment via GitHub Actions
- Production configuration
- Monitoring and maintenance

---

## 📋 Prerequisites

- Digital Ocean Droplet: `64.225.122.101`
- GitHub repository with your code
- SSH access to the droplet

---

## 🚀 Part 1: Server Setup (One-Time)

### 1.1 Connect to Your Droplet

```bash
ssh obeeoma@64.225.122.101
```

### 1.2 Update System and Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Configure firewall
sudo ufw allow OpenSSH
sudo ufw allow 80
sudo ufw allow 443
sudo ufw allow 8000
sudo ufw --force enable
```

### 1.3 Install Docker

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add obeeoma user to docker group
sudo usermod -aG docker obeeoma

# Log out and back in for group changes to take effect
exit
ssh obeeoma@64.225.122.101

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

---

## 🔑 Part 2: SSH Keys for GitHub Actions

### 2.1 Generate SSH Key

```bash
# Generate SSH key (no passphrase)
ssh-keygen -t ed25519 -C "github-actions"
# Press Enter for all prompts

# Add to authorized_keys
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Display private key - COPY THIS
cat ~/.ssh/id_ed25519
```

### 2.2 Add to GitHub Secrets

Go to your GitHub repository:
**Settings → Secrets and variables → Actions → New repository secret**

Add these secrets:
- `DROPLET_HOST`: `64.225.122.101`
- `DROPLET_USERNAME`: `obeeoma`
- `DROPLET_SSH_KEY`: (paste the entire private key from above)

---

## 📦 Part 3: Deploy Your Application

### 3.1 Clone Repository

```bash
# Clone your repository
cd ~
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git api
cd api
```

### 3.2 Create Environment File

```bash
nano .env
```

Add your configuration:

```env
# Django Settings
SECRET_KEY=your-production-secret-key-here
DEBUG=False
ALLOWED_HOSTS=64.225.122.101,localhost,127.0.0.1

# Database (Neon PostgreSQL)
DATABASE_URL=postgresql://user:password@host:5432/dbname
PGDATABASE=neondb
PGUSER=neondb_owner
PGPASSWORD=your-password
PGHOST=your-host.neon.tech
PGPORT=5432
PGSSLMODE=require

# Email Configuration
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=your-email@gmail.com

# Frontend URL
FRONTEND_URL=http://64.225.122.101

# API Base URL
API_BASE_URL=http://64.225.122.101:8000

# Google OAuth (if needed)
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
```

Save: `Ctrl+X`, `Y`, `Enter`

### 3.3 Build and Start Containers

```bash
# Build containers
docker-compose build

# Start services
docker-compose up -d

# Check status
docker ps
```

### 3.4 Run Initial Setup

```bash
# Run migrations
docker-compose exec backend python manage.py migrate

# Create superuser
docker-compose exec backend python manage.py createsuperuser

# Collect static files
docker-compose exec backend python manage.py collectstatic --noinput
```

---

## ✅ Part 4: Verify Deployment

### 4.1 Test Endpoints

Visit these URLs in your browser:

- **API Docs**: http://64.225.122.101:8000/api/v1/api/docs/
- **Admin Panel**: http://64.225.122.101:8000/admin/
- **API Root**: http://64.225.122.101:8000/api/v1/

### 4.2 Test with cURL

```bash
curl http://64.225.122.101:8000/api/v1/
```

---

## 🔄 Part 5: Automatic Deployments

### How It Works

1. You push code to `main` branch
2. GitHub Actions automatically triggers
3. Connects to your droplet via SSH
4. Pulls latest code
5. Rebuilds Docker containers
6. Runs migrations
7. Collects static files
8. Restarts services

### Manual Deployment

You can also trigger deployment manually:
1. Go to GitHub → Actions
2. Select "Deploy to DigitalOcean Droplet"
3. Click "Run workflow"

---

## 🛠️ Part 6: Useful Commands

### Docker Management

```bash
# View running containers
docker ps

# View logs
docker-compose logs -f backend
docker-compose logs -f nginx

# Restart services
docker-compose restart

# Stop services
docker-compose down

# Rebuild and restart
docker-compose up -d --build

# Clean up
docker system prune -f
```

### Django Management

```bash
# Run migrations
docker-compose exec backend python manage.py migrate

# Create superuser
docker-compose exec backend python manage.py createsuperuser

# Django shell
docker-compose exec backend python manage.py shell

# Check for issues
docker-compose exec backend python manage.py check
```

### Server Monitoring

```bash
# Check disk space
df -h

# Check memory
free -h

# Check processes
htop

# Check container stats
docker stats
```

---

## 🔒 Part 7: Security Hardening

### 7.1 Disable Root SSH Login

```bash
sudo nano /etc/ssh/sshd_config
```

Change:
```
PermitRootLogin no
PasswordAuthentication no
```

Restart SSH:
```bash
sudo systemctl restart sshd
```

### 7.2 Set Up SSL (Optional)

If you have a domain name:

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d yourdomain.com
```

### 7.3 Regular Updates

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Docker images
docker-compose pull
docker-compose up -d
```

---

## 🐛 Part 8: Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs backend

# Rebuild from scratch
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Database Connection Issues

```bash
# Test database connection
docker-compose exec backend python manage.py dbshell

# Check environment variables
docker-compose exec backend env | grep PG
```

### Static Files Not Loading

```bash
# Recollect static files
docker-compose exec backend python manage.py collectstatic --noinput --clear

# Restart nginx
docker-compose restart nginx
```

### Port Already in Use

```bash
# Find process using port
sudo lsof -i :8000

# Kill process
sudo kill -9 <PID>
```

### Deployment Failed

```bash
# Check GitHub Actions logs
# Go to: GitHub → Actions → Latest workflow run

# SSH to droplet and check
ssh obeeoma@64.225.122.101
cd ~/api
docker-compose logs --tail=100
```

---

## 📊 Part 9: Monitoring

### View Real-Time Logs

```bash
# All services
docker-compose logs -f

# Backend only
docker-compose logs -f backend

# Last 100 lines
docker-compose logs --tail=100 backend
```

### Check Container Health

```bash
# Container status
docker ps

# Resource usage
docker stats

# Inspect container
docker inspect django_backend
```

### Database Monitoring

```bash
# Connect to database
docker-compose exec backend python manage.py dbshell

# Check migrations
docker-compose exec backend python manage.py showmigrations
```

---

## 🎯 Quick Reference

### Your Deployment URLs

- **API Documentation**: http://64.225.122.101:8000/api/v1/api/docs/
- **Admin Panel**: http://64.225.122.101:8000/admin/
- **API Root**: http://64.225.122.101:8000/api/v1/

### GitHub Secrets Required

- `DROPLET_HOST`: 64.225.122.101
- `DROPLET_USERNAME`: obeeoma
- `DROPLET_SSH_KEY`: (SSH private key)

### Common Commands

```bash
# Deploy manually
git push origin main

# Check deployment status
ssh obeeoma@64.225.122.101 "cd ~/api && docker ps"

# View logs remotely
ssh obeeoma@64.225.122.101 "cd ~/api && docker-compose logs --tail=50 backend"

# Restart services
ssh obeeoma@64.225.122.101 "cd ~/api && docker-compose restart"
```

---

## ✨ Success Checklist

- [ ] Docker installed on droplet
- [ ] Deploy user created with SSH access
- [ ] GitHub secrets configured
- [ ] Repository cloned to `/home/deploy/api`
- [ ] `.env` file created with production settings
- [ ] Docker containers running
- [ ] Database migrations completed
- [ ] Superuser created
- [ ] API accessible at http://64.225.122.101:8000/api/v1/api/docs/
- [ ] Automatic deployment working on push to main

---

## 🎉 You're Done!

Your Django API is now deployed with:
- ✅ Docker containerization
- ✅ Nginx reverse proxy
- ✅ Automatic CI/CD deployments
- ✅ Production-ready configuration
- ✅ Zero-downtime updates

Every push to `main` branch will automatically deploy to your Digital Ocean droplet!

**Need help?** Check the troubleshooting section or review the logs.
