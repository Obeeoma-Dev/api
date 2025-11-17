#!/usr/bin/env python
"""
Debug script to check user's organization association
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from obeeomaapp.models import Organization, Employer, Employee, User

print("=" * 60)
print("USER ORGANIZATION DEBUG")
print("=" * 60)

# Get the user
email = "ainembabaziluciarachel02@gmail.com"
try:
    user = User.objects.get(email=email)
    print(f"\n✅ User found: {user.email}")
    print(f"   User ID: {user.id}")
    print(f"   Username: {user.username}")
    print(f"   Is Staff: {user.is_staff}")
    print(f"   Is Superuser: {user.is_superuser}")
except User.DoesNotExist:
    print(f"\n User not found: {email}")
    exit()

# Check Organization (owner)
print("\n--- ORGANIZATION (as owner) ---")
orgs = Organization.objects.filter(owner=user)
if orgs.exists():
    for org in orgs:
        print(f" Organization: {org.organizationName}")
        print(f"   ID: {org.id}")
        print(f"   Owner: {org.owner.email}")
else:
    print(" No organizations where user is owner")

# Check all Organizations
print("\n--- ALL ORGANIZATIONS ---")
all_orgs = Organization.objects.all()
if all_orgs.exists():
    for org in all_orgs:
        print(f"• {org.organizationName} (Owner: {org.owner.email if org.owner else 'None'})")
else:
    print(" No organizations in database")

# Check Employer
print("\n--- EMPLOYER ---")
employers = Employer.objects.all()
if employers.exists():
    for emp in employers:
        print(f"• {emp.name} (Active: {emp.is_active})")
else:
    print(" No employers in database")

# Check Employee profile
print("\n--- EMPLOYEE PROFILE ---")
try:
    employee = Employee.objects.get(user=user)
    print(f" Employee profile exists")
    print(f"   Employer: {employee.employer.name}")
    print(f"   Department: {employee.department.name if employee.department else 'None'}")
except Employee.DoesNotExist:
    print(" No employee profile for this user")

print("\n" + "=" * 60)
print("SOLUTION:")
print("=" * 60)

if not orgs.exists() and not employers.exists():
    print("You need to create an organization first:")
    print("POST /api/v1/organization-signup/")
elif not orgs.exists() and employers.exists():
    print("Organizations exist but user is not the owner.")
    print("Option 1: Update organization owner in database")
    print("Option 2: Make user staff: user.is_staff = True")
