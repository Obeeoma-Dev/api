# Render Deployment Guide

## Problem
Your Render deployment is failing with `no such table: obeeomaapp_organization` because:
1. The database tables haven't been created
2. Migrations haven't been run on Render

## Solution

### Step 1: Configure Render Service

In your Render dashboard (https://dashboard.render.com):

1. Go to your service settings
2. Set the **Build Command** to:
   ```bash
   ./build.sh
   ```

3. Set the **Start Command** to:
   ```bash
   ./start.sh
   ```
   OR
   ```bash
   gunicorn api.wsgi:application --bind 0.0.0.0:$PORT
   ```

### Step 2: Set Environment Variables

In Render dashboard → Environment tab, add these variables:

```
DATABASE_URL=postgresql://neondb_owner:npg_lN6DIUY7LigP@ep-rapid-wildflower-adyiip2d-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require

PGHOST=ep-rapid-wildflower-adyiip2d-pooler.c-2.us-east-1.aws.neon.tech
PGDATABASE=neondb
PGUSER=neondb_owner
PGPASSWORD=npg_lN6DIUY7LigP
PGSSLMODE=require

SECRET_KEY=your-secret-key-here
DEBUG=False

EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=obeeoma2025@gmail.com
EMAIL_HOST_PASSWORD=lrfmyzujlmemyrmy
DEFAULT_FROM_EMAIL=obeeoma2025@gmail.com

FRONTEND_URL=https://your-frontend-url.com
```

### Step 3: Deploy

1. Commit the new `build.sh` and `start.sh` files:
   ```bash
   git add build.sh start.sh
   git commit -m "Add Render build and start scripts"
   git push
   ```

2. Render will automatically redeploy

3. Check the logs to ensure migrations run successfully

### Step 4: Verify

After deployment, check:
- Build logs show: "Running migrations..."
- No "no such table" errors
- API endpoints work correctly

## Troubleshooting

### If migrations don't run:
1. Go to Render dashboard → Shell tab
2. Run manually:
   ```bash
   python manage.py migrate
   ```

### If still using SQLite:
- Make sure `DATABASE_URL` environment variable is set correctly
- Restart the service after adding environment variables

### Check logs:
```bash
# In Render dashboard → Logs tab
# Look for:
# - "Running migrations"
# - "Applying migrations"
# - Any database connection errors
```
