# Setting Up Google OAuth for Email on Digital Ocean

## Problem
Your invitation emails aren't being sent because Google OAuth credentials are missing on your Digital Ocean droplet.

---

## Solution: Add Google OAuth Credentials to Production

### Step 1: Generate OAuth2 Tokens (Run Locally)

You need to generate OAuth2 tokens locally first, then copy them to your droplet.

#### 1.1 Check if you have credentials.json

```bash
# Check if credentials.json exists
ls credentials.json
```

If it doesn't exist, you need to create it:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Enable **Gmail API**:
   - Go to "APIs & Services" → "Library"
   - Search for "Gmail API"
   - Click "Enable"
4. Create OAuth credentials:
   - Go to "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "OAuth client ID"
   - Choose "Desktop application"
   - Download the JSON file
   - Rename it to `credentials.json` and place it in your project root

#### 1.2 Install Required Packages (if not already installed)

```bash
pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client
```

#### 1.3 Run the OAuth Token Generator

```bash
python get_oauth2_token.py
```

This will:
- Open your browser
- Ask you to sign in with your Gmail account (obeeoma2025@gmail.com)
- Generate a refresh token
- Save it to `token.json` and `.env.template`

#### 1.4 Copy the Generated Credentials

After running the script, you'll see output like:

```
GOOGLE_CLIENT_ID=123456789.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abc123xyz
GOOGLE_REFRESH_TOKEN=1//0abc123xyz...
```

**COPY THESE VALUES!** You'll need them for the next step.

---

### Step 2: Add Credentials to Digital Ocean Droplet

#### 2.1 SSH to Your Droplet

```bash
ssh obeeoma@64.225.122.101
cd ~/api
```

#### 2.2 Edit the .env File

```bash
nano .env
```

#### 2.3 Add Google OAuth Credentials

Add these lines to your `.env` file (replace with your actual values):

```env
# Google OAuth for Gmail API
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-client-secret
GOOGLE_REFRESH_TOKEN=1//your-refresh-token
EMAIL_HOST_USER=obeeoma2025@gmail.com
DEFAULT_FROM_EMAIL=obeeoma2025@gmail.com
```

**Important:** Make sure these are the SAME credentials you generated locally!

Save the file: `Ctrl+X`, then `Y`, then `Enter`

#### 2.4 Verify the Configuration

```bash
# Check if the variables are set
cat .env | grep GOOGLE
```

You should see your three Google OAuth variables.

---

### Step 3: Restart Docker Containers

```bash
cd ~/api
docker-compose restart
```

Wait for containers to restart (about 10-20 seconds).

---

### Step 4: Test Email Sending

#### 4.1 Check Logs

```bash
docker-compose logs backend --tail=50 | grep -i email
```

#### 4.2 Send a Test Invitation

Use your API to send an invitation:

```bash
curl -X POST http://64.225.122.101:8000/api/v1/invitations/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "email": "rachelluciaainembabazi@gmail.com",
    "message": "Test invitation"
  }'
```

#### 4.3 Check Logs Again

```bash
docker-compose logs backend --tail=100 | grep -i "email\|gmail"
```

Look for:
- ✅ "Email sent via Gmail API to rachelluciaainembabazi@gmail.com"
- ❌ "Gmail API failed" (means credentials are wrong)
- ❌ "Failed to obtain OAuth2 credentials" (means env vars not set)

---

## Troubleshooting

### Issue 1: "Failed to obtain OAuth2 credentials"

**Cause:** Environment variables not set correctly on droplet

**Fix:**
```bash
ssh obeeoma@64.225.122.101
cd ~/api
cat .env | grep GOOGLE
# Make sure all three variables are there
docker-compose restart
```

---

### Issue 2: "Gmail API failed: invalid_grant"

**Cause:** Refresh token expired or invalid

**Fix:** Generate new tokens locally and update droplet:
```bash
# On your local machine
python get_oauth2_token.py

# Copy the new GOOGLE_REFRESH_TOKEN to droplet
ssh obeeoma@64.225.122.101
cd ~/api
nano .env
# Update GOOGLE_REFRESH_TOKEN
docker-compose restart
```

---

### Issue 3: "Gmail API failed: insufficient permissions"

**Cause:** OAuth scope doesn't include email sending

**Fix:** 
1. Delete `token.json` locally
2. Run `python get_oauth2_token.py` again
3. Make sure to authorize all requested permissions
4. Copy new refresh token to droplet

---

### Issue 4: Email still not received

**Possible causes:**
1. Check spam folder
2. Check logs: `docker-compose logs backend | grep -i email`
3. Verify Gmail account (obeeoma2025@gmail.com) can send emails
4. Check if Gmail API is enabled in Google Cloud Console

---

## Quick Verification Script

Run this on your droplet to verify everything is configured:

```bash
ssh obeeoma@64.225.122.101 << 'EOF'
cd ~/api
echo "=== Checking Google OAuth Configuration ==="
echo ""
echo "GOOGLE_CLIENT_ID:"
grep GOOGLE_CLIENT_ID .env | cut -d'=' -f2 | head -c 20
echo "..."
echo ""
echo "GOOGLE_CLIENT_SECRET:"
grep GOOGLE_CLIENT_SECRET .env | cut -d'=' -f2 | head -c 20
echo "..."
echo ""
echo "GOOGLE_REFRESH_TOKEN:"
grep GOOGLE_REFRESH_TOKEN .env | cut -d'=' -f2 | head -c 20
echo "..."
echo ""
echo "=== Checking Docker Containers ==="
docker ps | grep backend
echo ""
echo "=== Recent Email Logs ==="
docker-compose logs backend --tail=50 | grep -i "email\|gmail" | tail -10
EOF
```

---

## Complete .env Example for Droplet

Your `.env` file on the droplet should look like this:

```env
# Django Settings
SECRET_KEY=your-production-secret-key
DEBUG=False
ALLOWED_HOSTS=64.225.122.101,localhost,127.0.0.1

# Database (Neon)
DATABASE_URL=postgresql://neondb_owner:npg_lN6DIUY7LigP@ep-rapid-wildflower-adyiip2d-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require
PGHOST=ep-rapid-wildflower-adyiip2d-pooler.c-2.us-east-1.aws.neon.tech
PGDATABASE=neondb
PGUSER=neondb_owner
PGPASSWORD=npg_lN6DIUY7LigP
PGSSLMODE=require
PGCHANNELBINDING=require

# Google OAuth for Gmail API (REQUIRED FOR EMAIL)
GOOGLE_CLIENT_ID=123456789-abc.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-secret-here
GOOGLE_REFRESH_TOKEN=1//your-refresh-token-here
EMAIL_HOST_USER=obeeoma2025@gmail.com
DEFAULT_FROM_EMAIL=obeeoma2025@gmail.com

# Frontend
FRONTEND_URL=http://64.225.122.101

# OpenAI (if using)
OPENAI_API_KEY=your-key
OPENAI_MODEL=gpt-3.5-turbo

# Flutterwave (if using)
FLW_SEC_KEY=your-key
FLW_WEBHOOK_HASH=your-hash
```

---

## Summary

1. ✅ Generate OAuth tokens locally: `python get_oauth2_token.py`
2. ✅ Copy credentials to droplet `.env` file
3. ✅ Restart containers: `docker-compose restart`
4. ✅ Test by sending invitation
5. ✅ Check logs: `docker-compose logs backend | grep -i email`

**After following these steps, your invitation emails should be sent successfully via Gmail API!**
