# 📋 Deployment Checklist

Use this checklist to ensure smooth deployment to your DigitalOcean droplet.

## Pre-Deployment

- [ ] Commit all changes to GitHub
- [ ] Update `.env.example` with all required variables
- [ ] Test locally with Docker: `docker-compose up`
- [ ] Verify all tests pass
- [ ] Update `ALLOWED_HOSTS` in settings.py

## Droplet Setup

- [ ] Connect to droplet: `ssh root@64.225.122.101`
- [ ] Run setup script: `./setup-droplet.sh`
- [ ] Copy SSH private key from output
- [ ] Create deploy user (done by script)
- [ ] Install Docker (done by script)
- [ ] Configure firewall (done by script)

## GitHub Configuration

- [ ] Add `DROPLET_HOST` secret: `64.225.122.101`
- [ ] Add `DROPLET_USERNAME` secret: `deploy`
- [ ] Add `DROPLET_SSH_KEY` secret: (from setup script output)

## Application Setup

- [ ] Switch to deploy user: `su - deploy`
- [ ] Clone repository: `git clone <repo-url> /home/deploy/api`
- [ ] Create `.env` file with production values
- [ ] Update `SECRET_KEY` in `.env`
- [ ] Update database credentials in `.env`
- [ ] Update email credentials in `.env`
- [ ] Update `FRONTEND_URL` in `.env`

## Docker Deployment

- [ ] Build containers: `docker-compose build`
- [ ] Start containers: `docker-compose up -d`
- [ ] Check containers running: `docker ps`
- [ ] Run migrations: `docker-compose exec backend python manage.py migrate`
- [ ] Collect static files: `docker-compose exec backend python manage.py collectstatic --noinput`
- [ ] Create superuser: `docker-compose exec backend python manage.py createsuperuser`

## Testing

- [ ] Test API endpoint: `curl http://64.225.122.101/`
- [ ] Test admin panel: `http://64.225.122.101/admin/`
- [ ] Test API docs: `http://64.225.122.101/api/schema/swagger-ui/`
- [ ] Test authentication endpoints
- [ ] Test CORS from frontend
- [ ] Check logs: `docker-compose logs -f`

## CI/CD Verification

- [ ] Push to main branch
- [ ] Check GitHub Actions workflow runs
- [ ] Verify automatic deployment works
- [ ] Check deployment logs in GitHub Actions

## Security

- [ ] Change root password: `passwd`
- [ ] Disable root SSH login (optional)
- [ ] Set up SSL certificate (optional)
- [ ] Configure backup strategy
- [ ] Set up monitoring (optional)

## Post-Deployment

- [ ] Update frontend API URL to point to droplet
- [ ] Test end-to-end functionality
- [ ] Monitor logs for errors
- [ ] Set up database backups
- [ ] Document any custom configurations

## Troubleshooting Commands

```bash
# View all containers
docker ps -a

# View logs
docker-compose logs -f backend
docker-compose logs -f nginx

# Restart services
docker-compose restart

# Rebuild and restart
docker-compose down
docker-compose up -d --build

# Check Django logs
docker-compose exec backend python manage.py check

# Access Django shell
docker-compose exec backend python manage.py shell

# Check disk space
df -h

# Check memory
free -h
```

## Emergency Rollback

If deployment fails:

```bash
# Stop containers
docker-compose down

# Checkout previous commit
git checkout HEAD~1

# Rebuild and restart
docker-compose up -d --build
```

## Support

- Detailed guide: `DROPLET_DEPLOYMENT_GUIDE.md`
- Quick start: `QUICK_START.md`
- Docker issues: Check `docker-compose logs`
- GitHub Actions: Check workflow logs in GitHub
