"""Lightweight Gmail helper with graceful fallback when google libs are
not installed. Tests and environments that don't have Google API client
installed will still work — the send function will log and return False
instead of raising ImportError.
"""

import logging
import os
from base64 import urlsafe_b64encode
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from django.conf import settings

logger = logging.getLogger(__name__)


# Try to import google libraries; if unavailable, provide fallbacks so the
# module doesn't raise during import (useful for tests and constrained
# environments).
_google_available = True
try:
    from google.auth.transport.requests import Request  # type: ignore
    from google.oauth2.credentials import Credentials  # type: ignore
    from googleapiclient.discovery import build  # type: ignore
except Exception:  # pragma: no cover - environment dependent
    Request = None
    Credentials = None
    build = None
    _google_available = False


def get_oauth2_credentials():
    """Return Credentials or None if not available/refreshable."""
    if not _google_available:
        logger.debug("Google API client not available; skipping OAuth flow")
        return None

    try:
        # Try environment variable based refresh first
        if all(
            [
                getattr(settings, "GOOGLE_CLIENT_ID", None),
                getattr(settings, "GOOGLE_CLIENT_SECRET", None),
                getattr(settings, "GOOGLE_REFRESH_TOKEN", None),
            ]
        ):
            creds = Credentials(
                token=None,
                refresh_token=settings.GOOGLE_REFRESH_TOKEN,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=settings.GOOGLE_CLIENT_ID,
                client_secret=settings.GOOGLE_CLIENT_SECRET,
                scopes=["https://mail.google.com/"],
            )
            creds.refresh(Request())
            return creds

        # Fallback to token.json file
        if os.path.exists("token.json"):
            creds = Credentials.from_authorized_user_file(
                "token.json", ["https://mail.google.com/"]
            )
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
            return creds

    except Exception:  # pragma: no cover - error paths are network/env dependent
        # Log exception with traceback for diagnostics
        logger.exception("Error getting OAuth2 credentials")
        return None

    return None


def send_gmail_api_email(to_email, subject, body, html_body=None):
    """Send email using Gmail API with OAuth2. Supports both plain text and HTML.

    Args:
        to_email: Recipient email address
        subject: Email subject
        body: Plain text body
        html_body: Optional HTML body (if provided, creates multipart email)

    Returns True on success, False otherwise. If google libs aren't installed,
    returns False but does not raise.
    """
    if not _google_available:
        logger.debug(
            "send_gmail_api_email called but google libs missing; skipping send to %s",
            to_email,
        )
        return False

    try:
        creds = get_oauth2_credentials()
        if not creds:
            logger.error("Failed to obtain OAuth2 credentials for Gmail API")
            return False

        service = build("gmail", "v1", credentials=creds)

        # Create multipart message if HTML is provided
        if html_body:
            message = MIMEMultipart("alternative")
            message["to"] = to_email
            message["from"] = getattr(settings, "EMAIL_HOST_USER", "")
            message["subject"] = subject

            # Attach plain text version (fallback)
            text_part = MIMEText(body, "plain", "utf-8")
            message.attach(text_part)

            # Attach HTML version (preferred)
            html_part = MIMEText(html_body, "html", "utf-8")
            message.attach(html_part)
        else:
            # Plain text only
            message = MIMEText(body, "plain", "utf-8")
            message["to"] = to_email
            message["from"] = getattr(settings, "EMAIL_HOST_USER", "")
            message["subject"] = subject

        raw_message = urlsafe_b64encode(message.as_bytes()).decode()

        result = (
            service.users()
            .messages()
            .send(userId="me", body={"raw": raw_message})
            .execute()
        )

        logger.info(
            "Email sent successfully to %s. Message ID: %s", to_email, result.get("id")
        )
        return True

    except Exception as e:  # pragma: no cover - external network
        logger.error(f"Detailed error sending email to {to_email}: {str(e)}")
        logger.exception("Full traceback:")
        return False