# DigitalOcean Droplet Deployment Guide

Complete guide to deploy your Django backend on DigitalOcean with Docker and CI/CD.

## 📋 Prerequisites

- DigitalOcean Droplet: `64.225.122.101`
- Root password: `zH2ziSYAH2CxeknW`
- GitHub repository with your code

## 🚀 Step 1: Initial Server Setup

Connect to your droplet:
```bash
ssh root@64.225.122.101
# Password: zH2ziSYAH2CxeknW
```

Update system and create deploy user:
```bash
# Update system
apt update && apt upgrade -y

# Create deploy user
adduser deploy
# Set a password when prompted
usermod -aG sudo deploy

# Set up firewall
ufw allow OpenSSH
ufw allow 80
ufw allow 443
ufw allow 8000
ufw enable
```

## 🐳 Step 2: Install Docker

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Add deploy user to docker group
usermod -aG docker deploy

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

## 🔑 Step 3: Set Up SSH Keys for CI/CD

Switch to deploy user and generate SSH key:
```bash
# Switch to deploy user
su - deploy

# Generate SSH key
ssh-keygen -t ed25519 -C "github-actions"
# Press Enter for all prompts (no passphrase)

# Add key to authorized_keys
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Display private key (copy this for GitHub)
cat ~/.ssh/id_ed25519
```

## 📦 Step 4: Clone Your Repository

```bash
# As deploy user
cd /home/deploy
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git api
cd api
```

## 🔐 Step 5: Set Up Environment Variables

Create `.env` file on the droplet:
```bash
nano .env
```

Add your environment variables:
```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=64.225.122.101,localhost,127.0.0.1

# Database (if using external DB like Neon)
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

# Google OAuth (if using)
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REFRESH_TOKEN=your-refresh-token
```

Save and exit (Ctrl+X, Y, Enter)

## 🏗️ Step 6: Build and Run Docker Containers

```bash
# Build containers
docker-compose build

# Start containers
docker-compose up -d

# Check if containers are running
docker ps

# View logs
docker-compose logs -f
```

## 🔧 Step 7: Run Django Migrations

```bash
# Run migrations
docker-compose exec backend python manage.py migrate

# Create superuser (optional)
docker-compose exec backend python manage.py createsuperuser

# Collect static files
docker-compose exec backend python manage.py collectstatic --noinput
```

## 🔐 Step 8: Configure GitHub Secrets

Go to your GitHub repository:
1. Settings → Secrets and variables → Actions
2. Add these secrets:

- `DROPLET_HOST`: `64.225.122.101`
- `DROPLET_USERNAME`: `deploy`
- `DROPLET_SSH_KEY`: (paste the private key from `cat ~/.ssh/id_ed25519`)

## ✅ Step 9: Test Your Deployment

Visit in your browser:
- API: `http://64.225.122.101/`
- Admin: `http://64.225.122.101/admin/`
- API Docs: `http://64.225.122.101/api/schema/swagger-ui/`

Test API endpoint:
```bash
curl http://64.225.122.101/api/
```

## 🔄 Step 10: Automatic Deployments

Now when you push to `main` branch:
1. GitHub Actions will automatically trigger
2. Connect to your droplet
3. Pull latest code
4. Rebuild Docker containers
5. Restart services

## 📊 Useful Commands

### Docker Commands
```bash
# View running containers
docker ps

# View all containers
docker ps -a

# View logs
docker-compose logs -f backend
docker-compose logs -f nginx

# Restart services
docker-compose restart

# Stop services
docker-compose down

# Rebuild and restart
docker-compose up -d --build

# Clean up unused images
docker system prune -f
```

### Django Commands
```bash
# Run migrations
docker-compose exec backend python manage.py migrate

# Create superuser
docker-compose exec backend python manage.py createsuperuser

# Collect static files
docker-compose exec backend python manage.py collectstatic --noinput

# Django shell
docker-compose exec backend python manage.py shell
```

### Server Monitoring
```bash
# Check disk space
df -h

# Check memory usage
free -h

# Check running processes
htop

# Check nginx logs
docker-compose logs nginx

# Check backend logs
docker-compose logs backend
```

## 🔒 Security Recommendations

1. **Change root password**:
```bash
passwd
```

2. **Disable root SSH login**:
```bash
sudo nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
sudo systemctl restart sshd
```

3. **Set up SSL with Let's Encrypt** (optional):
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

4. **Regular updates**:
```bash
sudo apt update && sudo apt upgrade -y
```

## 🐛 Troubleshooting

### Container won't start
```bash
docker-compose logs backend
docker-compose down
docker-compose up -d --build
```

### Database connection issues
- Check `.env` file has correct DATABASE_URL
- Verify database is accessible from droplet
- Check firewall rules

### Static files not loading
```bash
docker-compose exec backend python manage.py collectstatic --noinput
docker-compose restart nginx
```

### Port already in use
```bash
sudo lsof -i :80
sudo lsof -i :8000
# Kill the process or change ports in docker-compose.yml
```

## 📝 Next Steps

1. ✅ Set up domain name (optional)
2. ✅ Configure SSL certificate
3. ✅ Set up database backups
4. ✅ Configure monitoring (e.g., Sentry)
5. ✅ Set up log aggregation

## 🎉 Success!

Your Django backend is now deployed on DigitalOcean with:
- ✅ Docker containerization
- ✅ Nginx reverse proxy
- ✅ Automatic CI/CD with GitHub Actions
- ✅ Production-ready configuration

Visit: `http://64.225.122.101/`
