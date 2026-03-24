#!/usr/bin/env python
import os
import django

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from django.contrib.auth import get_user_model
from obeeomaapp.models import EmployeeProfile

User = get_user_model()

print("=== User Role Check ===")
# Get all users and their roles
users = User.objects.all()
for user in users:
    try:
        profile = EmployeeProfile.objects.get(user=user)
        print(f"User: {user.email} | Role: {profile.role}")
    except EmployeeProfile.DoesNotExist:
        print(f"User: {user.email} | No EmployeeProfile")

print("\n=== Current User ===")
# Check current logged-in user (you'd need to be logged in)
print("To check current user role, you need to be logged in through Django admin or have a session")
