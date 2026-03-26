#!/usr/bin/env python
import os
import sys
import django
from django.contrib.auth import get_user_model
from django.db.models import Count

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from obeeomaapp.models import (
    Employee, EmployeeProfile, Organization, OnboardingState,
    PSS10Assessment, MentalHealthAssessment
)

User = get_user_model()

print("=== DATABASE INVESTIGATION ===")
print()

# Check total users by role
print("USERS BY ROLE:")
users_by_role = User.objects.values('role').annotate(count=Count('role'))
for item in users_by_role:
    print(f"  {item['role']}: {item['count']}")

print()

# Check employees vs users
print("EMPLOYEE RECORDS:")
total_users = User.objects.filter(role='employee').count()
employee_records = Employee.objects.count()
print(f"  Users with role='employee': {total_users}")
print(f"  Employee records: {employee_records}")

print()

# Check onboarding status
print("ONBOARDING STATUS:")
employees = User.objects.filter(role='employee')
onboarded_count = employees.filter(onboarding_completed=True).count()
not_onboarded_count = employees.filter(onboarding_completed=False).count()
print(f"  Onboarded employees: {onboarded_count}")
print(f"  Not onboarded employees: {not_onboarded_count}")

print()

# Check EmployeeProfile records
print("EMPLOYEE PROFILE RECORDS:")
profile_count = EmployeeProfile.objects.count()
print(f"  EmployeeProfile records: {profile_count}")

# Show recent employee profiles
recent_profiles = EmployeeProfile.objects.select_related(
    'user'
).order_by('-joined_on')[:5]
print("  Recent employee profiles:")
for profile in recent_profiles:
    print(
        f"    {profile.user.email} - {profile.display_name} - "
        f"Joined: {profile.joined_on}"
    )

print()

# Check OnboardingState records
print("ONBOARDING STATE RECORDS:")
onboarding_states = OnboardingState.objects.count()
print(f"  OnboardingState records: {onboarding_states}")

# Show recent onboarding states
recent_onboarding = OnboardingState.objects.select_related(
    'user'
).order_by('-id')[:5]
print("  Recent onboarding states:")
for state in recent_onboarding:
    print(
        f"    {state.user.email} - Completed: {state.completed} - "
        f"First Action: {state.first_action_done}"
    )

print()

# Check assessment records
print("ASSESSMENT RECORDS:")
mental_health_count = MentalHealthAssessment.objects.count()
pss10_count = PSS10Assessment.objects.count()
print(f"  MentalHealthAssessment records: {mental_health_count}")
print(f"  PSS10Assessment records: {pss10_count}")

print()

# Show organizations and their employee counts
print("ORGANIZATIONS:")
orgs = Organization.objects.all()
for org in orgs:
    employee_count = User.objects.filter(
        organization=org, role='employee'
    ).count()
    print(f"  {org.organizationName}: {employee_count} employees")

print()
print("=== END INVESTIGATION ===")
