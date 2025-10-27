import os
import json
import logging
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

class OAuthTokenManager:
    def __init__(self):
        self.credentials = None
        self.service = None
        self.token_key = 'gmail_oauth_token'
    
    def get_credentials(self):
        """Get or refresh OAuth credentials with caching"""
        # Try to get from cache first
        cached_creds = cache.get(self.token_key)
        if cached_creds:
            self.credentials = Credentials.from_authorized_user_info(cached_creds)
            if not self.credentials.expired:
                return self.credentials
        
        # Create new credentials
        self.credentials = Credentials(
            token=None,
            refresh_token=settings.GOOGLE_REFRESH_TOKEN,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            scopes=settings.GMAIL_SCOPES
        )
        
        # Always refresh to get a valid access token
        try:
            self.credentials.refresh(Request())
            
            # Cache the token info (expires in 1 hour)
            token_info = {
                'token': self.credentials.token,
                'refresh_token': self.credentials.refresh_token,
                'token_uri': self.credentials.token_uri,
                'client_id': self.credentials.client_id,
                'client_secret': self.credentials.client_secret,
                'scopes': self.credentials.scopes,
            }
            cache.set(self.token_key, token_info, 3500)  # Cache for 58 minutes
            
            logger.info("OAuth token refreshed and cached successfully")
            return self.credentials
            
        except Exception as e:
            logger.error(f"Failed to refresh OAuth token: {str(e)}")
            cache.delete(self.token_key)  # Clear invalid cache
            return None
    
    def get_gmail_service(self):
        """Get authenticated Gmail service"""
        creds = self.get_credentials()
        if not creds:
            return None
        
        try:
            service = build('gmail', 'v1', credentials=creds, cache_discovery=False)
            return service
        except Exception as e:
            logger.error(f"Failed to create Gmail service: {str(e)}")
            return None

# Global instance
token_manager = OAuthTokenManager()