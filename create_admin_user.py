#!/usr/bin/env python
"""
Script to create a system admin user with a specific email.
This will bypass MFA setup for testing purposes.
"""

import os
import sys
import django

# Add the project directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'obeeomaapp.settings')
django.setup()

from obeeomaapp.models import User
from django.core.exceptions import ValidationError

def create_system_admin():
    """Create a system admin user with your email"""
    
    # Get your email from environment or use a default
    email = os.environ.get('ADMIN_EMAIL', 'mikeangelodonatelo@gmail.com')
    
    # Check if user already exists
    if User.objects.filter(email=email).exists():
        user = User.objects.get(email=email)
        print(f"✅ User {email} already exists with role: {user.role}")
        
        # Update to system admin if not already
        if user.role != 'system_admin':
            user.role = 'system_admin'
            user.is_staff = True
            user.is_superuser = True
            user.mfa_enabled = False  # Disable MFA for testing
            user.save()
            print(f"🔄 Updated user role to system_admin and disabled MFA")
        else:
            print(f"ℹ️  User is already a system admin")
        
        return user
    
    # Create new system admin user
    try:
        # Use your specified password
        password = 'NansubugaGideon'
        
        user = User.objects.create_user(
            email=email,
            password=password,
            role='system_admin',
            is_staff=True,
            is_superuser=True,
            onboarding_completed=True,
            is_first_time=False,
            mfa_enabled=True,  # Enable MFA so you get codes on your phone
        )
        
        # Generate MFA secret for this user
        import pyotp
        mfa_secret = pyotp.random_base32()
        user.mfa_secret = mfa_secret
        user.save()
        
        # Generate QR code URL for easy setup
        totp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(
            name=email,
            issuer_name="Obeeoma System Admin"
        )
        
        print(f"✅ Successfully created system admin user:")
        print(f"   Email: {email}")
        print(f"   Password: {password}")
        print(f"   Role: {user.role}")
        print(f"   MFA Enabled: {user.mfa_enabled}")
        print(f"   MFA Secret: {mfa_secret}")
        print(f"   Is Staff: {user.is_staff}")
        print(f"   Is Superuser: {user.is_superuser}")
        print(f"\n📱 To setup MFA on your phone:")
        print(f"   1. Install Google Authenticator or Authy")
        print(f"   2. Scan this QR code or enter secret manually:")
        print(f"   QR Code URL: {totp_uri}")
        print(f"   Manual entry key: {mfa_secret}")
        
        return user
        
    except ValidationError as e:
        print(f"❌ Error creating user: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None

def list_all_users():
    """List all users in the system"""
    print("\n📋 All users in the system:")
    print("-" * 80)
    for user in User.objects.all():
        print(f"Email: {user.email}")
        print(f"Role: {user.role}")
        print(f"Is Staff: {user.is_staff}")
        print(f"Is Superuser: {user.is_superuser}")
        print(f"MFA Enabled: {user.mfa_enabled}")
        print(f"Organization: {user.organization}")
        print("-" * 40)

if __name__ == "__main__":
    print("🔧 Creating System Admin User...")
    print("=" * 50)
    
    # Create the admin user
    admin_user = create_system_admin()
    
    if admin_user:
        print(f"\n✅ Success! You can now login with:")
        print(f"   Email: {admin_user.email}")
        print(f"   Password: NansubugaGideon")
        print(f"   MFA: Enabled - Check your phone for codes")
        
        # List all users
        list_all_users()
    else:
        print("\n❌ Failed to create admin user")
        sys.exit(1)
