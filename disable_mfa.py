#!/usr/bin/env python
"""
Disable MFA for the system admin user for testing purposes
"""

import os
import sys
import django

# Add the project directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from obeeomaapp.models import User

def disable_mfa():
    """Disable MFA for the system admin user"""
    email = 'mikeangelodonatelo@gmail.com'
    
    try:
        user = User.objects.get(email=email)
        user.mfa_enabled = False
        user.mfa_secret = None
        user.save()
        
        print(f"✅ MFA disabled for {email}")
        print(f"   MFA Enabled: {user.mfa_enabled}")
        print(f"   MFA Secret: {user.mfa_secret}")
        print(f"\n🔓 You can now login without MFA!")
        
    except User.DoesNotExist:
        print(f"❌ User {email} not found")

if __name__ == "__main__":
    disable_mfa()
