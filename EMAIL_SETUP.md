# Email Verification Setup Guide

## Overview
This API now includes a complete email verification system for password reset functionality that works on both localhost and Render.

## Features
- ✅ Password reset with email verification codes
- ✅ 6-digit verification codes that expire in 15 minutes
- ✅ HTML email templates
- ✅ Works on both localhost and production (Render)
- ✅ Secure token-based verification
- ✅ Console email backend for development

## Setup Instructions

### 1. Environment Variables
Create a `.env` file in your project root with the following variables:

```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
PORT=8000

# Database Configuration
DATABASE_URL=postgresql://username:password@host:port/database_name

# Email Configuration (for Gmail)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_USE_SSL=False
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=your-email@gmail.com
```

### 2. Gmail App Password Setup
1. Enable 2-factor authentication on your Gmail account
2. Go to Google Account settings > Security > App passwords
3. Generate a new app password for "Mail"
4. Use this app password as `EMAIL_HOST_PASSWORD` (not your regular Gmail password)

### 3. For Development (Console Email)
If you want to see emails in the console during development, set:
```env
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
```

### 4. For Production (Render)
Set up the environment variables in your Render dashboard:
- `EMAIL_HOST_USER`: Your Gmail address
- `EMAIL_HOST_PASSWORD`: Your Gmail app password
- `DEFAULT_FROM_EMAIL`: Your Gmail address

## API Endpoints

### Password Reset Request
**POST** `/auth/reset-password/`

Request body:
```json
{
    "email": "user@example.com"
}
```

Response:
```json
{
    "message": "Password reset code sent to user@example.com",
    "token": "generated-token-here"
}
```

### Password Reset Confirmation
**POST** `/auth/reset-password/confirm/`

Request body:
```json
{
    "code": "123456",
    "new_password": "newpassword123",
    "confirm_password": "newpassword123",
    "token": "generated-token-here"
}
```

Response:
```json
{
    "message": "Password reset successfully"
}
```

## Testing

### Localhost Testing
1. Set up your `.env` file with Gmail credentials
2. Run the Django server: `python manage.py runserver`
3. Test the password reset endpoint
4. Check your Gmail inbox for the verification code

### Console Testing (Development)
1. Set `EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend` in your `.env`
2. Run the server and check the console output for email content

## Security Features
- ✅ Verification codes expire in 15 minutes
- ✅ Codes can only be used once
- ✅ Secure token generation
- ✅ No user enumeration (same response whether email exists or not)
- ✅ Password validation

## Troubleshooting

### Email not sending
1. Check your Gmail app password is correct
2. Ensure 2FA is enabled on your Gmail account
3. Check the Django logs for error messages
4. Verify environment variables are set correctly

### Code not working
1. Ensure the code hasn't expired (15 minutes)
2. Check that the token matches the one returned from the reset request
3. Verify the code is exactly 6 digits

## Migration
The system automatically creates the necessary database tables. Run:
```bash
python manage.py makemigrations
python manage.py migrate
```
