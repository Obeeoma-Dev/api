#!/usr/bin/env python
import os
import django

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'obeeomaapp.settings')
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

# Create or update system admin with known password
try:
    user = User.objects.filter(email='admin@obeeoma.com').first()
    if user:
        print('Updating existing admin user...')
        user.role = 'system_admin'
        user.onboarding_completed = True  # Admins don't need onboarding
        user.is_first_time = False
        user.set_password('admin123')
        user.save()
        print('✅ Updated admin user')
    else:
        print('Creating new system admin...')
        user = User.objects.create_user(
            email='admin@obeeoma.com',
            password='admin123',
            role='system_admin'
        )
        user.onboarding_completed = True
        user.is_first_time = False
        user.save()
        print('✅ Created new system admin')
    
    print(f'System Admin Ready:')
    print(f'   Email: admin@obeeoma.com')
    print(f'   Password: admin123')
    print(f'   Role: {user.role}')
    print(f'   Onboarding Required: NO (bypassed for system_admin)')
    
except Exception as e:
    print(f'Error: {e}')
