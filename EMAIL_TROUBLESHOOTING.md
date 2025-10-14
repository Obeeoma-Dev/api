# 🔧 Email Delivery Troubleshooting Guide

## 🚨 Current Issue: Emails Not Being Delivered on Render

Based on your screenshot, the API is responding successfully but emails aren't reaching your inbox. Here's how to fix this:

## 🔍 Step 1: Check Your Email Configuration

Visit this URL to see your current email configuration:
```
https://api-0904.onrender.com/debug/email-config/
```

This will show you:
- Email backend being used
- SMTP host and port
- Whether TLS is enabled
- Your email credentials status

## 🛠 Step 2: Set Up Environment Variables on Render

Go to your Render dashboard → Your Service → Environment tab and add these variables:

### Required Variables:
```
EMAIL_HOST_USER=your-gmail@gmail.com
EMAIL_HOST_PASSWORD=your-gmail-app-password
DEFAULT_FROM_EMAIL=your-gmail@gmail.com
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_USE_SSL=False
```

### ⚠️ Important Notes:
1. **Use Gmail App Password**: Don't use your regular Gmail password
2. **Enable 2FA**: You must have 2-factor authentication enabled on Gmail
3. **Generate App Password**: Go to Google Account → Security → App passwords

## 📧 Step 3: Gmail App Password Setup

1. **Enable 2-Factor Authentication** on your Gmail account
2. **Go to Google Account Settings** → Security → App passwords
3. **Generate a new app password** for "Mail"
4. **Use this 16-character password** (not your regular password)

## 🔍 Step 4: Test Email Configuration

After setting up environment variables:

1. **Redeploy your service** on Render
2. **Test the password reset** again
3. **Check the debug endpoint**: `https://api-0904.onrender.com/debug/email-config/`
4. **Look for error messages** in the response

## 🐛 Step 5: Common Issues & Solutions

### Issue 1: "Authentication failed"
- **Solution**: Check your Gmail app password
- **Make sure**: 2FA is enabled and you're using app password, not regular password

### Issue 2: "Connection refused"
- **Solution**: Check EMAIL_HOST and EMAIL_PORT
- **Should be**: smtp.gmail.com and 587

### Issue 3: "TLS/SSL error"
- **Solution**: Set EMAIL_USE_TLS=True and EMAIL_USE_SSL=False

### Issue 4: "No credentials"
- **Solution**: Make sure EMAIL_HOST_USER and EMAIL_HOST_PASSWORD are set

## 📱 Step 6: Alternative Email Services

If Gmail doesn't work, try these alternatives:

### SendGrid (Recommended for production):
```
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=apikey
EMAIL_HOST_PASSWORD=your-sendgrid-api-key
```

### Mailgun:
```
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.mailgun.org
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-mailgun-smtp-username
EMAIL_HOST_PASSWORD=your-mailgun-smtp-password
```

## 🔍 Step 7: Debug Information

The updated code now includes debug information in responses. When you test password reset, you'll see:

```json
{
  "message": "Password reset code sent to your-email@gmail.com",
  "token": "generated-token",
  "debug_info": {
    "email_backend": "django.core.mail.backends.smtp.EmailBackend",
    "email_host": "smtp.gmail.com",
    "from_email": "your-email@gmail.com"
  }
}
```

If there's an error, you'll see:
```json
{
  "error": "Failed to send email. Please try again later.",
  "debug_error": "Actual error message here",
  "debug_info": {
    "email_backend": "...",
    "email_host": "...",
    "from_email": "..."
  }
}
```

## 🚀 Step 8: Test Again

1. **Set up environment variables** on Render
2. **Redeploy** your service
3. **Test password reset** with your email
4. **Check your Gmail inbox** (including spam folder)
5. **Check the debug endpoint** for configuration status

## 📞 Need Help?

If you're still having issues:
1. Check the debug endpoint response
2. Look at Render logs for error messages
3. Verify your Gmail app password is correct
4. Make sure all environment variables are set

The most common issue is using the wrong password (regular Gmail password instead of app password) or not having 2FA enabled.
