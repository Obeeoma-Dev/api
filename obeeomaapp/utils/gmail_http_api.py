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
    """
    Initialize and return Gmail API service
    """
    try:
        token_file = os.environ.get('GMAIL_TOKEN_FILE', 'token.json')
        
        if not os.path.exists(token_file):
            logger.error(f"Token file {token_file} not found")
            return None
            
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
        service = build('gmail', 'v1', credentials=creds)
        return service
    except Exception as e:
        logger.error(f"Error initializing Gmail service: {str(e)}")
        return None

def send_email(service, to_email, subject, message_text):
    """
    Send an email using Gmail API
    """
    try:
        message = MIMEText(message_text)
        message['to'] = to_email
        message['subject'] = subject
        
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
        body = {'raw': raw_message}
        
        message = service.users().messages().send(userId='me', body=body).execute()
        logger.info(f"Email sent successfully. Message ID: {message['id']}")
        return True
        
    except HttpError as error:
        logger.error(f"HTTP error sending email: {error}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending email: {str(e)}")
        return False

def send_gmail_api_email(to_email, subject, body):
    """
    Wrapper function to match your existing code
    """
    service = get_gmail_service()
    if service:
        return send_email(service, to_email, subject, body)
    else:
        logger.error("Failed to initialize Gmail service")
        return False
