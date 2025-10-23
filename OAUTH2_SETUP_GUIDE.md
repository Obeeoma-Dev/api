# OAuth2 Gmail API Setup Guide

## Step 1: Google Cloud Console Setup

### 1.1 Create/Configure Google Cloud Project
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the Gmail API:
   - Go to "APIs & Services" > "Library"
   - Search for "Gmail API"
   - Click "Enable"

### 1.2 Create OAuth2 Credentials
1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth client ID"
3. Choose "Web application"
4. Add authorized redirect URIs:
   - https://developers.google.com/oauthplayground (for testing)
   - Your production domain (when ready)
5. Download the credentials JSON file

## Step 2: Get Refresh Token

### 2.1 Using OAuth2 Playground (Recommended for testing)
1. Go to [OAuth2 Playground](https://developers.google.com/oauthplayground/)
2. Click the gear icon (⚙) in top right
3. Check "Use your own OAuth credentials"
4. Enter your Client ID and Client Secret
5. In the left panel, find "Gmail API v1"
6. Select https://www.googleapis.com/auth/gmail.send
7. Click "Authorize APIs"
8. Sign in with your Gmail account
9. Click "Exchange authorization code for tokens"
10. Copy the *Refresh Token* (you'll need this)

### 2.2 Alternative: Using Python Script
python
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle
import os

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def get_refresh_token():
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json', SCOPES)
    creds = flow.run_local_server(port=0)
    
    # Save credentials for future use
    with open('token.json', 'w') as token:
        token.write(creds.to_json())
    
    print(f"Refresh Token: {creds.refresh_token}")
    return creds.refresh_token


## Step 3: Environment Configuration

Create a .env file in your project root:
env
# Gmail OAuth2 Configuration
DEFAULT_FROM_EMAIL=icpauej@gmail.com
EMAIL_HOST_USER=icpauej@gmail.com

# Google OAuth2 Credentials
GOOGLE_CLIENT_ID=your_client_id_from_google_cloud
GOOGLE_CLIENT_SECRET=your_client_secret_from_google_cloud
GOOGLE_REFRESH_TOKEN=your_refresh_token_from_oauth_playground

# Optional: OAuth2 Redirect URI
GOOGLE_REDIRECT_URI=https://developers.google.com/oauthplayground


## Step 4: Install Required Packages

bash
pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib


## Step 5: Code Configuration

Your gmail_http_api.py is already set up correctly. The main changes needed are:

1. Update email backend in settings.py
2. Modify views to use Gmail API instead of Django's send_mail
3. Ensure proper error handling

## Step 6: Testing

1. Set up your .env file with real credentials
2. Test email sending through your API endpoints
3. Check Gmail sent folder to verify emails are being sent

## Troubleshooting

### Common Issues:
1. *"Invalid credentials"*: Check your Client ID and Secret
2. *"Refresh token expired"*: Get a new refresh token from OAuth Playground
3. *"Access denied"*: Ensure Gmail API is enabled in Google Cloud Console
4. *"Quota exceeded"*: Check Gmail API quotas in Google Cloud Console

### Security Notes:
- Never commit your .env file to version control
- Use environment variables in production
- Regularly rotate your refresh tokens
- Monitor API usage in Google Cloud Console

## Production Considerations:
- Use a proper OAuth2 flow for production
- Implement token refresh logic
- Add proper error handling and logging
- Consider using service accounts for server-to-server communication