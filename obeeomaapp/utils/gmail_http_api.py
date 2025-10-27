# gmail_sender.py

import os
import base64
import logging
from email.mime.text import MIMEText
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

SCOPES = ['https://mail.google.com/', 'https://www.googleapis.com/auth/gmail.send']

def get_gmail_service():
    try:
        creds = Credentials.from_authorized_user_info({
            'client_id': os.getenv('GOOGLE_CLIENT_ID'),
            'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
            'refresh_token': os.getenv('REFRESH_TOKEN')
        }, SCOPES)
        return build('gmail', 'v1', credentials=creds, cache_discovery=False)
    except Exception as e:
        logger.error(f"Failed to create Gmail service: {str(e)}")
        return None

def send_gmail_api_email(to_email, subject, body):
    try:
        service = get_gmail_service()
        if not service:
            logger.error("Gmail service not available")
            return False

        message = MIMEText(body)
        message['to'] = to_email
        message['subject'] = subject
        message['from'] = os.getenv('EMAIL_HOST_USER', 'obeeoma256@gmail.com')

        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except HttpError as error:
        logger.error(f"Gmail API error: {error}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending email: {str(e)}")
        return False
