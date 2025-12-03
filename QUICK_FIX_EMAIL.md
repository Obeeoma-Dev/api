# 🚀 Quick Fix: Google OAuth Email Not Working

## The Problem
Invitation API returns success but email not received because Google OAuth credentials are missing on your Digital Ocean droplet.

---

## ⚡ Quick Fix (5 minutes)

### Step 1: Check Current Status

Run this script to see what's missing:

```bash
bash check-oauth-droplet.sh
```

Or manually check:

```bash
ssh obeeoma@64.225.122.101 "cd ~/api && cat .env | grep GOOGLE"
```

---

### Step 2: Generate OAuth Tokens (If Not Already Done)

**On your local machine:**

```bash
# Make sure you have credentials.json in your project root
# If not, download it from Google Cloud Console

# Run the token generator
python get_oauth2_token.py
```

This will output something like:

```
GOOGLE_CLIENT_ID=123456789-abc.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abc123xyz
GOOGLE_REFRESH_TOKEN=1//0abc123xyz...
```

**COPY THESE VALUES!**

---

### Step 3: Add to Droplet

```bash
# SSH to droplet
ssh obeeoma@64.225.122.101

# Go to api directory
cd ~/api

# Edit .env file
nano .env
```

**Add these lines** (replace with your actual values from Step 2):

```env
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-client-secret
GOOGLE_REFRESH_TOKEN=1//your-refresh-token
EMAIL_HOST_USER=obeeoma2025@gmail.com
DEFAULT_FROM_EMAIL=obeeoma2025@gmail.com
```

**Save:** Press `Ctrl+X`, then `Y`, then `Enter`

---

### Step 4: Restart Containers

```bash
docker-compose restart
```

Wait 10-20 seconds for containers to restart.

---

### Step 5: Test

Send an invitation and check logs:

```bash
# Check logs for email sending
docker-compose logs backend --tail=50 | grep -i email

# You should see:
# ✅ "Email sent via Gmail API to rachelluciaainembabazi@gmail.com"
```

---

## 🔍 Verify It's Working

### Check logs in real-time:

```bash
ssh obeeoma@64.225.122.101
cd ~/api
docker-compose logs -f backend | grep -i email
```

Then send an invitation from your app and watch the logs.

### Expected success log:

```
Email sent via Gmail API to rachelluciaainembabazi@gmail.com
```

### If you see errors:

- `"Failed to obtain OAuth2 credentials"` → Env vars not set correctly
- `"Gmail API failed: invalid_grant"` → Refresh token expired, regenerate
- `"Gmail API failed"` → Check credentials are correct

---

## 📋 Checklist

- [ ] Generated OAuth tokens locally (`python get_oauth2_token.py`)
- [ ] Added `GOOGLE_CLIENT_ID` to droplet `.env`
- [ ] Added `GOOGLE_CLIENT_SECRET` to droplet `.env`
- [ ] Added `GOOGLE_REFRESH_TOKEN` to droplet `.env`
- [ ] Added `EMAIL_HOST_USER=obeeoma2025@gmail.com` to droplet `.env`
- [ ] Restarted containers (`docker-compose restart`)
- [ ] Tested by sending invitation
- [ ] Checked logs (`docker-compose logs backend | grep -i email`)
- [ ] Email received (check inbox and spam)

---

## 🆘 Still Not Working?

### 1. Check if Gmail API is enabled

Go to [Google Cloud Console](https://console.cloud.google.com/)
- Select your project
- Go to "APIs & Services" → "Library"
- Search "Gmail API"
- Make sure it's **ENABLED**

### 2. Regenerate tokens

```bash
# Delete old token
rm token.json

# Generate new one
python get_oauth2_token.py

# Copy new credentials to droplet
```

### 3. Check detailed logs

```bash
ssh obeeoma@64.225.122.101
cd ~/api
docker-compose logs backend --tail=200 | grep -i -E "(email|gmail|oauth|invitation)"
```

### 4. Test OAuth credentials locally first

Before deploying to droplet, test locally:

```bash
# Add credentials to your local .env
# Then test sending an invitation locally
# If it works locally, it should work on droplet with same credentials
```

---

## 💡 Pro Tip

Keep your OAuth credentials in a secure note/password manager. You'll need them for:
- Production deployment (Digital Ocean)
- Staging environments
- Local development
- Disaster recovery

---

## 📚 Full Documentation

- **Complete guide:** `SETUP_GOOGLE_OAUTH_EMAIL.md`
- **Check script:** `bash check-oauth-droplet.sh`
- **Token generator:** `python get_oauth2_token.py`

---

**That's it! Your emails should now be sent via Google OAuth API. 🎉**
