from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from email.mime.text import MIMEText
import base64
import os
import pickle

class GmailBackend:
    def __init__(self):
        self.creds = None
        self.SCOPES = ['https://mail.google.com/', 'https://www.googleapis.com/auth/gmail.send']
        
    def get_credentials(self):
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                self.creds = pickle.load(token)
                
        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
            else:
                self.creds = Credentials.from_authorized_user_info({
                    'client_id': os.getenv('GOOGLE_CLIENT_ID'),
                    'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
                    'refresh_token': os.getenv('REFRESH_TOKEN')
                }, self.SCOPES)
                
            with open('token.pickle', 'wb') as token:
                pickle.dump(self.creds, token)
                
        return self.creds

    def send_email(self, to, subject, body):
        try:
            creds = self.get_credentials()
            service = build('gmail', 'v1', credentials=creds)
            
            message = MIMEText(body)
            message['to'] = to
            message['subject'] = subject
            
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
            
            service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()
            
            return True
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return False