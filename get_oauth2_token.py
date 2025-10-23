#!/usr/bin/env python
"""
OAuth2 Token Generator Script
This script helps you get the correct refresh token for Gmail API
"""

import json
import os

from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow

# Gmail API scopes
SCOPES = ["https://mail.google.com/"]


def get_refresh_token():
    """
    Get OAuth2 refresh token for Gmail API
    """
    print(" OAuth2 Token Generator for Gmail API")
    print("=" * 50)

    # Check if credentials.json exists
    if not os.path.exists("credentials.json"):
        print(" credentials.json not found!")
        print("\nTo get credentials.json:")
        print("1. Go to Google Cloud Console (https://console.cloud.google.com/)")
        print("2. Create/select a project")
        print("3. Enable Gmail API")
        print("4. Go to 'Credentials' > 'Create Credentials' > 'OAuth client ID'")
        print("5. Choose 'Desktop application'")
        print("6. Download the JSON file and rename it to 'credentials.json'")
        return None

    try:
        # Create the flow
        flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)

        print(" Opening browser for OAuth2 authorization...")
        print("   Please sign in with your Gmail account")

        # Run the flow
        creds = flow.run_local_server(port=0)

        # Save credentials
        with open("token.json", "w") as token_file:
            token_file.write(creds.to_json())

        print("\n OAuth2 setup complete!")
        print(f" Refresh Token: {creds.refresh_token}")
        print(" Token saved to: token.json")

        # Create .env template
        env_content = f"""# Add these to your .env file
DEFAULT_FROM_EMAIL=obeeoma2025@gmail.com
EMAIL_HOST_USER=obeeoma2025@gmail.com
GOOGLE_CLIENT_ID={creds.client_id}
GOOGLE_CLIENT_SECRET={creds.client_secret}
GOOGLE_REFRESH_TOKEN={creds.refresh_token}
"""

        with open(".env.template", "w") as env_file:
            env_file.write(env_content)

        print(" .env template created: .env.template")
        print("\n You can now test your OAuth2 setup!")

        return creds.refresh_token

    except Exception as e:
        print(f" Error: {e}")
        return None


if __name__ == "_main_":
    get_refresh_token()