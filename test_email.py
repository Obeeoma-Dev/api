import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from django.core.mail import send_mail
from django.conf import settings

print("Email Backend:", settings.EMAIL_BACKEND)
print("Email Host:", settings.EMAIL_HOST)
print("Email Port:", settings.EMAIL_PORT)
print("Email User:", settings.EMAIL_HOST_USER)
print("Email Password set:", bool(settings.EMAIL_HOST_PASSWORD))
print("Email Use TLS:", settings.EMAIL_USE_TLS)
print("\nSending test email...")

try:
    result = send_mail(
        subject='Test Email from Obeeoma',
        message='This is a test email to verify SMTP configuration.',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=['jkulabako@student.refactory.academy'],
        fail_silently=False,
    )
    print(f"Email sent successfully! Result: {result}")
except Exception as e:
    print(f"Error sending email: {str(e)}")
    import traceback
    traceback.print_exc()
