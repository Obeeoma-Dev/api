#!/usr/bin/env python
"""
Test invitation endpoint directly
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from obeeomaapp.models import User, Organization, Employer, EmployeeInvitation
from rest_framework.test import APIRequestFactory, force_authenticate
from obeeomaapp.views import InviteView

print("=" * 60)
print("TESTING INVITATION ENDPOINT")
print("=" * 60)

# Get the user
email = "ainembabaziluciarachel02@gmail.com"
try:
    user = User.objects.get(email=email)
    print(f"\n User found: {user.email}")
except User.DoesNotExist:
    print(f"\n User not found: {email}")
    exit()

# Check if user has organization
org = Organization.objects.filter(owner=user).first()
if org:
    print(f" Organization: {org.organizationName}")
else:
    print("  No organization found for user")
    print("Creating test organization...")
    org = Organization.objects.create(
        organizationName="Test Company",
        owner=user,
        industry="Technology",
        size="10-50"
    )
    print(f" Created organization: {org.organizationName}")

# Create test invitation
print("\n--- Creating Invitation ---")
factory = APIRequestFactory()
request = factory.post('/api/v1/invitations/', {
    'email': 'testemployee@example.com',
    'message': 'Welcome to our team!'
}, format='json')

# Authenticate the request
force_authenticate(request, user=user)

# Call the view
view = InviteView.as_view({'post': 'create'})
response = view(request)

print(f"\nStatus Code: {response.status_code}")
print(f"Response: {response.data}")

if response.status_code == 201:
    print("\n SUCCESS! Invitation created")
    
    # Show the invitation
    invitation = EmployeeInvitation.objects.latest('created_at')
    print(f"\nInvitation Details:")
    print(f"  Email: {invitation.email}")
    print(f"  Token: {invitation.token}")
    print(f"  Expires: {invitation.expires_at}")
    print(f"  Employer: {invitation.employer.name}")
else:
    print("\n FAILED!")
    print("Error details:", response.data)

print("\n" + "=" * 60)
