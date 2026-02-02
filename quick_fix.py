#!/usr/bin/env python
import os
import django

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'obeeomaapp.settings')
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

# Create a test user with onboarding completed
try:
    # Check if user already exists
    user = User.objects.filter(email='quicktest@example.com').first()
    if user:
        print('User already exists, updating onboarding status...')
        user.onboarding_completed = True
        user.is_first_time = False
        user.set_password('testpass123')  # Reset password
        user.save()
        print('Updated existing user with completed onboarding')
    else:
        print('Creating new user with completed onboarding...')
        user = User.objects.create_user(
            email='quicktest@example.com',
            password='testpass123',
            role='employee'
        )
        user.onboarding_completed = True
        user.is_first_time = False
        user.save()
        print('Created new user with completed onboarding')
    
    print(f'✅ Quick test user ready:')
    print(f'   Email: quicktest@example.com')
    print(f'   Password: testpass123')
    print(f'   Onboarding Completed: {user.onboarding_completed}')
    print(f'   Role: {user.role}')
    
except Exception as e:
    print(f'Error: {e}')
