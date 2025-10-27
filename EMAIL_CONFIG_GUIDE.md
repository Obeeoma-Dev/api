# Email Configuration Guide for Localhost

## Current Issues:
1. FIXED: Added DEFAULT_FROM_EMAIL setting
2. ISSUE: Using console email backend (emails only print to console)
3. ISSUE: OAuth2 credentials not configured
4. ISSUE: Gmail API not being used




### Option 2: Use OAuth2 Gmail API (Production ready)
Add these to your .env file:

DEFAULT_FROM_EMAIL=obeeoma2025@gmail.com
EMAIL_HOST_USER=obeeoma2025@gmail.com
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
GOOGLE_REFRESH_TOKEN=your_refresh_token


### Option 3: Test with Console (Current setup)
Emails will only appear in your Django console/logs, not sent to recipients.

## To Enable Real Email Sending:
1. Create a .env file in your project root
2. Add the configuration above
3. Update settings.py to use the appropriate backend
4. For OAuth2: Set up Google Cloud Console and get credentials
5. For SMTP: Enable 2FA and create an app password in Gmail

## Current Status:
- DEFAULT_FROM_EMAIL setting added
- Still using console backend (emails not sent to recipients)
- Need to configure OAuth2 or SMTP credentials