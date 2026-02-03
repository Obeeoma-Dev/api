#!/usr/bin/env python
"""
Check if there's any mood tracking data in the database
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from obeeomaapp.models import MoodTracking, CompanyMood, EmployeeProfile
from django.contrib.auth import get_user_model

User = get_user_model()

print("=" * 60)
print("MOOD TRACKING DATA CHECK")
print("=" * 60)

# Check MoodTracking entries
mood_count = MoodTracking.objects.count()
print(f"\n1. MoodTracking Entries: {mood_count}")

if mood_count > 0:
    print("\n   Recent mood entries:")
    for mood in MoodTracking.objects.all()[:5]:
        print(f"   - {mood.user.email}: {mood.mood} at {mood.checked_in_at}")
    
    print("\n   Mood distribution:")
    from django.db.models import Count
    distribution = MoodTracking.objects.values('mood').annotate(count=Count('mood')).order_by('-count')
    for item in distribution:
        print(f"   - {item['mood']}: {item['count']}")
else:
    print("   ❌ No mood tracking data found!")
    print("   💡 Employees need to log their moods first")

# Check CompanyMood entries
company_mood_count = CompanyMood.objects.count()
print(f"\n2. CompanyMood Entries: {company_mood_count}")

if company_mood_count > 0:
    print("\n   Recent company mood summaries:")
    for cm in CompanyMood.objects.all()[:3]:
        print(f"   - {cm.created_at}: {cm.summary_description[:100]}...")
else:
    print("   ℹ️  No company mood summaries (these are manually created)")

# Check employees
employee_count = EmployeeProfile.objects.count()
print(f"\n3. Employee Profiles: {employee_count}")

if employee_count > 0:
    print(f"   ✅ {employee_count} employees can track mood")
else:
    print("   ❌ No employee profiles found!")

print("\n" + "=" * 60)
print("RECOMMENDATIONS:")
print("=" * 60)

if mood_count == 0:
    print("\n❌ NO MOOD DATA - Frontend won't show anything")
    print("\nTo fix:")
    print("1. Employees must log their mood via:")
    print("   POST /api/v1/employee/mood-tracking/")
    print("   Body: {\"mood\": \"Happy\"}")
    print("\n2. Or create test data:")
    print("   python manage.py shell")
    print("   >>> from obeeomaapp.models import MoodTracking, EmployeeProfile")
    print("   >>> emp = EmployeeProfile.objects.first()")
    print("   >>> MoodTracking.objects.create(user=emp.user, employee=emp, mood='Happy')")
else:
    print("\n✅ Mood data exists - should display on frontend")
    print(f"   Endpoint: GET /api/v1/employee/mood-tracking/employer-summary/")

print("\n")
