# Email Not Being Received - Debugging Guide

## Problem
Invitation API returns success but email is not received by the recipient.

## Likely Causes

### 1. **Gmail API Credentials Not Configured in Production**
Your code tries Gmail API first, then falls back to SMTP. If neither is properly configured, the email won't send.

### 2. **Environment Variables Missing**
The `.env` file on your Digital Ocean droplet might be missing email configuration.

### 3. **Email Logs Not Being Checked**
The code logs email sending attempts, but you need to check the logs.

---

## Quick Fix Steps

### Step 1: Check Docker Logs

```bash
ssh obeeoma@64.225.122.101
cd ~/api
docker-compose logs backend | grep -i email
docker-compose logs backend | grep -i "invitation"
```

Look for messages like:
- "Email sent via Gmail API"
- "Gmail API failed"
- "Email sent via SMTP"
- "SMTP failed"
- "Failed to send invitation email"

### Step 2: Verify Environment Variables

```bash
ssh obeeoma@64.225.122.101
cd ~/api
cat .env | grep EMAIL
cat .env | grep GOOGLE
```

You should see:
```env
# For Gmail API (preferred)
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REFRESH_TOKEN=your-refresh-token
EMAIL_HOST_USER=your-email@gmail.com

# OR for SMTP (fallback)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=your-email@gmail.com
```

### Step 3: Test Email Manually

Create a test script on your droplet:

```bash
ssh obeeoma@64.225.122.101
cd ~/api
docker-compose exec backend python manage.py shell
```

Then run:
```python
from django.core.mail import send_mail
from django.conf import settings

# Test SMTP
send_mail(
    'Test Email',
    'This is a test',
    settings.DEFAULT_FROM_EMAIL,
    ['rachelluciaainembabazi@gmail.com'],
    fail_silently=False,
)
```

---

## Solutions

### Solution 1: Use SMTP (Easiest)

1. **Get Gmail App Password**:
   - Go to: https://myaccount.google.com/apppasswords
   - Generate an app password for "Mail"
   - Copy the 16-character password

2. **Update .env on droplet**:
```bash
ssh obeeoma@64.225.122.101
cd ~/api
nano .env
```

Add/update these lines:
```env
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-16-char-app-password
DEFAULT_FROM_EMAIL=your-email@gmail.com
```

3. **Restart containers**:
```bash
docker-compose restart
```

4. **Test again**:
Send another invitation and check if email arrives.

---

### Solution 2: Use Gmail API (More Complex)

If you want to use Gmail API, you need to:

1. **Generate OAuth2 tokens** (run locally):
```bash
python get_oauth2_token.py
```

2. **Copy tokens to .env**:
```env
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REFRESH_TOKEN=your-refresh-token
EMAIL_HOST_USER=your-email@gmail.com
```

3. **Restart containers**:
```bash
ssh obeeoma@64.225.122.101
cd ~/api
docker-compose restart
```

---

## Verification Checklist

After applying the fix:

- [ ] Environment variables are set in `.env`
- [ ] Containers restarted: `docker-compose restart`
- [ ] Check logs: `docker-compose logs backend | grep -i email`
- [ ] Send test invitation
- [ ] Check email inbox (including spam folder)
- [ ] Check logs again for success/error messages

---

## Common Issues

### Issue: "Authentication failed"
**Cause**: Wrong email password or app password not generated
**Fix**: Generate Gmail app password at https://myaccount.google.com/apppasswords

### Issue: "SMTPAuthenticationError"
**Cause**: 2-factor authentication enabled but using regular password
**Fix**: Use app password instead of regular password

### Issue: Email goes to spam
**Cause**: Email not properly configured with SPF/DKIM
**Fix**: 
- Check spam folder first
- Add sender to contacts
- Consider using a transactional email service (SendGrid, Mailgun)

### Issue: "Connection refused"
**Cause**: Firewall blocking SMTP port 587
**Fix**: 
```bash
sudo ufw allow 587/tcp
```

---

## Quick Diagnostic Command

Run this on your droplet to see all email-related logs:

```bash
ssh obeeoma@64.225.122.101 "cd ~/api && docker-compose logs backend --tail=200 | grep -i -E '(email|smtp|gmail|invitation)'"
```

---

## Recommended Solution

**Use SMTP with Gmail App Password** - It's the simplest and most reliable:

1. Generate app password: https://myaccount.google.com/apppasswords
2. Add to `.env` on droplet
3. Restart containers
4. Test

This should resolve your email delivery issue!
