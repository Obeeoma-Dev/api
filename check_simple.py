
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from obeeomaapp.models import Employee, Department, MoodTracking

print("=" * 60)
print("SIMPLE DATABASE CHECK")
print("=" * 60)

# Check what tables exist
print("\n=== EMPLOYEES ===")
try:
    total = Employee.objects.count()
    print(f"Employee table exists")
    print(f"  Total Employees: {total}")
    
    if total > 0:
        print("\n  Sample Employees:")
        for emp in Employee.objects.all()[:5]:
            print(f"    • {emp.first_name} {emp.last_name} - {emp.email} ({emp.status})")
    else:
        print(" No employees in database yet")
except Exception as e:
    print(f"Employee table error: {e}")

print("\n=== DEPARTMENTS ===")
try:
    total = Department.objects.count()
    print(f"Department table exists")
    print(f"  Total Departments: {total}")
    
    if total > 0:
        for dept in Department.objects.all()[:5]:
            print(f"    • {dept.name}")
    else:
        print("No departments in database yet")
except Exception as e:
    print(f" Department table error: {e}")

print("\n=== MOOD TRACKING ===")
try:
    total = MoodTracking.objects.count()
    print(f"MoodTracking table exists")
    print(f"Total Entries: {total}")
    
    if total == 0:
        print("No mood tracking entries yet")
except Exception as e:
    print(f"MoodTracking table error: {e}")

print("\n" + "=" * 60)
print("=" * 60)
