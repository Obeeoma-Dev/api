
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from obeeomaapp.models import (
    Employee, AssessmentResponse, MoodTracking, 
    Department, OrganizationActivity, SavedResource
)

print("=" * 60)
print("DATABASE OVERVIEW")
print("=" * 60)

# EMPLOYEES
print("\n=== EMPLOYEES ===")
total_employees = Employee.objects.count()
active_employees = Employee.objects.filter(status='active').count()
inactive_employees = Employee.objects.filter(status='inactive').count()
suspended_employees = Employee.objects.filter(status='suspended').count()

print(f"Total Employees: {total_employees}")
print(f"  - Active: {active_employees}")
print(f"  - Inactive: {inactive_employees}")
print(f"  - Suspended: {suspended_employees}")

print("\nSample Employees:")
for emp in Employee.objects.select_related('department')[:5]:
    dept_name = emp.department.name if emp.department else 'N/A'
    print(f"  • {emp.first_name} {emp.last_name} - {emp.email}")
    print(f"    Dept: {dept_name}, Status: {emp.status}")

# ASSESSMENTS
print("\n=== ASSESSMENTS ===")
total_assessments = AssessmentResponse.objects.count()
unique_users_assessed = AssessmentResponse.objects.values('user').distinct().count()

print(f"Total Assessment Responses: {total_assessments}")
print(f"Unique Users with Assessments: {unique_users_assessed}")

if total_assessments > 0:
    print("\nSample Assessments:")
    for assessment in AssessmentResponse.objects.select_related('user')[:3]:
        print(f"  • User: {assessment.user.username if assessment.user else 'N/A'}")
        print(f"    Type: {assessment.assessment_type}, Score: {assessment.total_score}, Severity: {assessment.severity_level}")

# MOOD TRACKING
print("\n=== MOOD TRACKING ===")
total_mood_entries = MoodTracking.objects.count()
unique_users_mood = MoodTracking.objects.values('user').distinct().count()

print(f"Total Mood Entries: {total_mood_entries}")
print(f"Unique Users with Mood Tracking: {unique_users_mood}")

if total_mood_entries > 0:
    print("\nSample Mood Entries:")
    for mood in MoodTracking.objects.select_related('user')[:3]:
        print(f"  • User: {mood.user.username if mood.user else 'N/A'}")
        print(f"    Mood: {mood.mood}, Date: {mood.checked_in_at}")

# DEPARTMENTS
print("\n=== DEPARTMENTS ===")
total_departments = Department.objects.count()
print(f"Total Departments: {total_departments}")

if total_departments > 0:
    print("\nDepartments:")
    for dept in Department.objects.all()[:10]:
        emp_count = dept.employees.count()
        print(f"  • {dept.name} ({emp_count} employees)")

# ORGANIZATION ACTIVITIES
print("\n=== ORGANIZATION ACTIVITIES ===")
total_activities = OrganizationActivity.objects.count()
print(f"Total Activities: {total_activities}")

if total_activities > 0:
    print("\nRecent Activities:")
    for activity in OrganizationActivity.objects.order_by('-created_at')[:5]:
        dept_name = activity.department.name if activity.department else 'General'
        print(f"  • {activity.description}")
        print(f"    Dept: {dept_name}, Date: {activity.created_at}")

# SAVED RESOURCES
print("\n=== SAVED RESOURCES ===")
total_saved = SavedResource.objects.count()
unique_users_saved = SavedResource.objects.values('user').distinct().count()
print(f"Total Saved Resources: {total_saved}")
print(f"Unique Users with Saved Resources: {unique_users_saved}")

print("\n" + "=" * 60)
print("END OF DATABASE OVERVIEW")
print("=" * 60)
