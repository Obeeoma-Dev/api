import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from django.contrib.auth import get_user_model
from obeeomaapp.models import Employee

User = get_user_model()

print("=" * 60)
print("USERS IN DATABASE")
print("=" * 60)

# Get all users
users = User.objects.all()
print(f"Total users: {users.count()}")

print("\n=== ALL USERS ===")
for user in users:
    print(f"• Email: {user.email}")
    print(f"  Role: {user.role}")
    print(f"  Is Staff: {user.is_staff}")
    print(f"  Is Superuser: {user.is_superuser}")
    print(f"  Is Active: {user.is_active}")
    print(f"  Organization: {user.organization.name if user.organization else 'None'}")
    print(f"  Onboarding Completed: {user.onboarding_completed}")
    print(f"  Last Login: {user.last_login}")
    print()

print("\n=== EMPLOYEE PROFILES ===")
employees = Employee.objects.all()
print(f"Total employee profiles: {employees.count()}")

for emp in employees.select_related('user', 'department')[:10]:
    print(f"• User: {emp.user.email}")
    print(f"  Name: {emp.first_name} {emp.last_name}")
    print(f"  Department: {emp.department.name if emp.department else 'None'}")
    print(f"  Status: {emp.status}")
    print()

print("\n=== POTENTIAL LOGIN CREDENTIALS ===")
print("You can try these email addresses for login:")
print("(Note: You'll need the corresponding passwords)")

# Show active users that could potentially login
active_users = User.objects.filter(is_active=True)
for user in active_users:
    if user.is_superuser or user.is_staff or user.role in ['system_admin', 'employer']:
        print(f"🔑 {user.email} ({user.role})")
    else:
        print(f"👤 {user.email} ({user.role})")

print("\n" + "=" * 60)
print("END OF USER LIST")
print("=" * 60)
