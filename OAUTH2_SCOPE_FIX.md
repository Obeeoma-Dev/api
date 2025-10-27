# OAuth2 Scope Error Fix Guide

## The Problem:
The error invalid_scope: Bad Request occurs because:
1. The scope https://www.googleapis.com/auth/gmail.send is deprecated
2. You need to use the correct Gmail API scope
3. Your refresh token might have been generated with the wrong scope

## Solution Steps:

### Step 1: Use Correct Scope  (FIXED)
I've updated your code to use: https://mail.google.com/
This is the correct scope for Gmail API access.

### Step 2: Get New Refresh Token
Since your current refresh token was generated with the wrong scope, you need a new one:

1. *Go to OAuth2 Playground*: https://developers.google.com/oauthplayground/
2. *Click the gear icon (⚙)* in the top right
3. *Check "Use your own OAuth credentials"*
4. *Enter your credentials*:
   - OAuth Client ID: your_client_id
   - OAuth Client secret: your_client_secret
5. *In the left panel*, find "Gmail API v1"
6. *Select the scope*: https://mail.google.com/ (NOT the old gmail.send scope)
7. *Click "Authorize APIs"*
8. *Sign in* with your Gmail account
9. *Click "Exchange authorization code for tokens"*
10. *Copy the NEW Refresh Token*

### Step 3: Update Your .env File
env
DEFAULT_FROM_EMAIL=icpauej@gmail.com
EMAIL_HOST_USER=icpauej@gmail.com
GOOGLE_CLIENT_ID=your_client_id_here
GOOGLE_CLIENT_SECRET=your_client_secret_here
GOOGLE_REFRESH_TOKEN=your_NEW_refresh_token_here


### Step 4: Test Again
bash
python test_oauth2.py


## Alternative: Use More Specific Scope
If you prefer a more restrictive scope, you can also use:
- https://www.googleapis.com/auth/gmail.compose (for composing/sending emails)

But https://mail.google.com/ is the most reliable and commonly used scope.

## Why This Happened:
- Google deprecated the old gmail.send scope
- The OAuth2 Playground might have cached old scopes
- Your refresh token was generated with the deprecated scope

## Quick Fix Summary:
1. Updated code to use correct scope
2. Get new refresh token with correct scope
3. Update .env file with new token
4. Test again

The scope error should be resolved once you get a new refresh token with the correct scope!