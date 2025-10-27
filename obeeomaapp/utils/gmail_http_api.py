import base64
import logging
import email.utils
from email.mime.text import MIMEText
from googleapiclient.errors import HttpError
from django.conf import settings
from .gmail_oauth_backend import token_manager

logger = logging.getLogger(__name__)

def create_message(sender, to, subject, message_text):
    """
    Create a MIME email message and encode it for Gmail API
    """
    try:
        msg = MIMEText(message_text, _charset='utf-8')
        msg['To'] = to
        msg['From'] = sender
        msg['Subject'] = subject
        msg['Reply-To'] = sender
        msg['Message-ID'] = email.utils.make_msgid()

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        return {'raw': raw}
    except Exception as e:
        logger.error(f"Error creating email message: {str(e)}")
        return None

def send_gmail_api_email(to_email, subject, body):
    """
    Send email using Gmail API with OAuth2 and automatic token refresh
    """
    try:
        logger.info(f"Attempting to send email to: {to_email}")
        service = token_manager.get_gmail_service()
        if not service:
            logger.error("Gmail service not available - check OAuth configuration")
            return False

        message = create_message(settings.EMAIL_HOST_USER, to_email, subject, body)
        if not message:
            logger.error("Failed to create email message")
            return False

        sent_message = service.users().messages().send(userId="me", body=message).execute()
        logger.info(f"Email sent successfully to {to_email}. Message ID: {sent_message.get('id')}")
        return True

    except HttpError as error:
        logger.error(f"Gmail API error: {error.resp.status} - {error._get_reason()}")
        if error.resp.status in [401, 403]:
            from django.core.cache import cache
            cache.delete('gmail_oauth_token')
            logger.info("Cleared OAuth token cache due to authentication error")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending email: {str(e)}")
        return False

def test_gmail_connection():
    """
    Test Gmail API connection and log the authenticated email address
    """
    try:
        service = token_manager.get_gmail_service()
        if service:
            profile = service.users().getProfile(userId='me').execute()
            logger.info(f"Gmail connection test successful for: {profile.get('emailAddress')}")
            return True
        return False
    except Exception as e:
        logger.error(f"Gmail connection test failed: {str(e)}")
        return False
