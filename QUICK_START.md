# 🚀 Quick Start - Deploy to DigitalOcean

Follow these steps to deploy your Django backend to your DigitalOcean droplet.

## Step 1: Connect to Your Droplet

```bash
ssh root@64.225.122.101
# Password: zH2ziSYAH2CxeknW
```

## Step 2: Run Setup Script

Copy the setup script to your droplet and run it:

```bash
# Download and run setup script
curl -o setup.sh https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/setup-droplet.sh
chmod +x setup.sh
./setup.sh
```

Or manually copy the content of `setup-droplet.sh` and run it.

## Step 3: Copy SSH Key to GitHub

The setup script will display an SSH private key. Copy it and:

1. Go to your GitHub repo → Settings → Secrets and variables → Actions
2. Add these secrets:
   - `DROPLET_HOST`: `64.225.122.101`
   - `DROPLET_USERNAME`: `deploy`
   - `DROPLET_SSH_KEY`: (paste the private key)

## Step 4: Clone Repository

```bash
# Switch to deploy user
su - deploy

# Clone your repository
cd /home/deploy
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git api
cd api
```

## Step 5: Configure Environment

```bash
# Copy example env file
cp .env.example .env

# Edit with your values
nano .env
```

Update these important values:
- `SECRET_KEY`: Generate a new one
- `PGPASSWORD`, `PGHOST`: Your Neon DB credentials
- `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`: Your email credentials
- `GOOGLE_CLIENT_ID`, etc.: Your OAuth credentials (if using)

## Step 6: Deploy

```bash
# Build and start containers
docker-compose up -d

# Run migrations
docker-compose exec backend python manage.py migrate

# Create superuser (optional)
docker-compose exec backend python manage.py createsuperuser

# Check if running
docker ps
```

## Step 7: Test

Visit: `http://64.225.122.101/`

## Step 8: Push to GitHub

Now every time you push to `main` branch, GitHub Actions will automatically deploy!

```bash
git add .
git commit -m "Add Docker deployment"
git push origin main
```

## 🎉 Done!

Your API is now live at: `http://64.225.122.101/`

## Useful Commands

```bash
# View logs
docker-compose logs -f

# Restart services
docker-compose restart

# Stop services
docker-compose down

# Rebuild
docker-compose up -d --build
```

## Need Help?

Check `DROPLET_DEPLOYMENT_GUIDE.md` for detailed instructions and troubleshooting.
