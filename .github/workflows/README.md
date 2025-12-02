# GitHub Actions Workflows

## Active Workflows ✅

### `tests.yml` - Main Test Pipeline
- **Status:** ACTIVE
- **Runs on:** Every push and PR to main
- **Purpose:** Run all tests to ensure code quality
- **Expected Result:** GREEN ✅

## Disabled Workflows ⏸️

The following workflows are **disabled** (only run manually via workflow_dispatch):

### `deploy-droplet.yml` - DigitalOcean Deployment
- **Status:** DISABLED
- **Reason:** Not deploying yet, shifting to DigitalOcean soon
- **To enable:** Uncomment the `push:` trigger and add required secrets

### `CI_CD.yml` - Old CI/CD Pipeline
- **Status:** DISABLED
- **Reason:** Replaced by tests.yml

### `api-ci_cd.yml` - API CI/CD Pipeline
- **Status:** DISABLED
- **Reason:** Replaced by tests.yml

### `django.yml` - Django CI
- **Status:** DISABLED
- **Reason:** Replaced by tests.yml

## How to Re-enable Deployment

When ready to deploy to DigitalOcean:

1. Add these secrets to GitHub:
   - `DROPLET_HOST` - Your DigitalOcean droplet IP
   - `DROPLET_USERNAME` - SSH username (usually 'root' or 'deploy')
   - `DROPLET_SSH_KEY` - Your private SSH key

2. Uncomment the `push:` trigger in `deploy-droplet.yml`

3. Push to main branch

## Current Status

✅ **Tests:** Running and passing (45/45)
⏸️ **Deployment:** Disabled until DigitalOcean setup is complete
