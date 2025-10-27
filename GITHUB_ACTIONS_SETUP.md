# GitHub Actions Setup Guide

## Required GitHub Secrets Configuration

To make your GitHub Actions pass, you need to configure the following secrets in your repository.

### How to Add Secrets:

1. Go to your repository: https://github.com/Lucy-dev1999/api
2. Click **Settings** (top menu)
3. Click **Secrets and variables** → **Actions** (left sidebar)
4. Click **New repository secret** button

---

## Secrets to Add:

### 1. CI/CD Testing Secrets (Required)

| Secret Name | Value | Purpose |
|------------|-------|---------|
| `DJANGO_SECRET_KEY_CI` | `test-secret-key-for-ci-only-12345` | Django secret key for testing |
| `DATABASE_URL_CI` | `sqlite:///db.sqlite3` | Use SQLite for fast CI testing |

### 2. Render Deployment Secrets (Required for deployment)

| Secret Name | Where to Find | Purpose |
|------------|---------------|---------|
| `RENDER_API_KEY` | Render Dashboard → Account Settings → API Keys | Authenticate with Render API |
| `RENDER_SERVICE_ID` | Render Dashboard → Your Service → Settings → Service ID | Identify your service |
| `RENDER_DEPLOY_HOOK_URL` | Render Dashboard → Your Service → Settings → Deploy Hook | Trigger deployments |

**How to get Render values:**
- Go to https://dashboard.render.com
- Select your service
- Go to Settings tab
- Find the values listed above

### 3. Neon Database Secrets (Optional - for PR preview environments)

| Name | Type | Where to Find | Purpose |
|------|------|---------------|---------|
| `NEON_API_KEY` | Secret | Neon Console → Account Settings → API Keys | Authenticate with Neon |
| `NEON_PROJECT_ID` | Variable* | Neon Console → Your Project → Project ID | Identify your project |

**Note:** `NEON_PROJECT_ID` should be added as a **Variable**, not a Secret:
- Click on **Variables** tab (next to Secrets)
- Click **New repository variable**

---

## What Each Workflow Does:

### 1. `api-ci_cd.yml` (Main CI/CD)
- Runs on: Push to main, Pull requests
- Tests with: Python 3.12 and 3.13
- Steps:
  - Lints code with flake8
  - Checks for pending migrations
  - Collects static files
  - Runs Django tests
  - Deploys to Render (on main branch only)

### 2. `CI_CD.yml` (Alternative CI/CD)
- Similar to above but simpler
- Tests with: Python 3.12 only
- Deploys using Render deploy hook

### 3. `neon.yml` (PR Preview Databases)
- Creates temporary Neon database branches for PRs
- Deletes them when PR is closed
- Useful for testing with real PostgreSQL

---

## Troubleshooting:

### If tests fail:
1. Check the Actions tab on GitHub to see error messages
2. Make sure all secrets are configured correctly
3. Verify your tests pass locally: `python manage.py test`

### If deployment fails:
1. Verify Render secrets are correct
2. Check Render dashboard for deployment logs
3. Make sure your Render service is properly configured

### If linting fails:
Run locally to fix issues:
```bash
pip install flake8
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
```

---

## Current Status:

✅ Database settings updated to support SQLite for CI
✅ Code pushed to GitHub
⏳ Waiting for you to add GitHub secrets
⏳ Waiting for GitHub Actions to run

Once you add the secrets, the next push will trigger the workflows and they should pass!
