from django.core.mail import send_mail
from django.conf import settings

send_mail(
    subject='Test Email from Obeeoma',
    message='This is a test to verify your email configuration.',
    from_email=settings.DEFAULT_FROM_EMAIL,
    recipient_list=['josephinekentrhines@gmail.com'],
    fail_silently=False
)
