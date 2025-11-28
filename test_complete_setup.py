"""
Test script to verify the complete account setup flow
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from obeeomaapp.serializers import EmployeeInvitationAcceptSerializer
from obeeomaapp.models import EmployeeInvitation
from django.utils import timezone

print("=" * 50)
print("Testing Complete Account Setup")
print("=" * 50)

# Check if serializer has create method
print(f"\n1. Serializer has 'create' method: {hasattr(EmployeeInvitationAcceptSerializer, 'create')}")

# Check for invitations that are ready for account setup
invitations = EmployeeInvitation.objects.filter(
    accepted=False,
    credentials_used=True,
    expires_at__gt=timezone.now()
).order_by('-created_at')

print(f"\n2. Found {invitations.count()} invitation(s) ready for account setup:")
for inv in invitations:
    print(f"   - Email: {inv.email}")
    print(f"   - Employer: {inv.employer.name}")
    print(f"   - Credentials used: {inv.credentials_used}")
    print(f"   - Accepted: {inv.accepted}")
    print(f"   - Expires: {inv.expires_at}")
    print()

# Test serializer validation
print("\n3. Testing serializer with sample data...")
test_data = {
    'username': 'testuser123',
    'password': 'TestPass123!',
    'confirm_password': 'TestPass123!'
}

serializer = EmployeeInvitationAcceptSerializer(data=test_data)
if serializer.is_valid():
    print("   ✅ Serializer validation passed!")
    print(f"   Found invitation: {serializer.validated_data.get('invitation')}")
else:
    print("   ❌ Serializer validation failed:")
    print(f"   Errors: {serializer.errors}")

print("\n" + "=" * 50)
