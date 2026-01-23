# EmployeeProfile Fix for ChatSessionView

## Problem
The ChatSessionView.perform_create() method fails with 500 error when users don't have an EmployeeProfile record.

## Solution
Replace the perform_create method in obeeomaapp/views.py (around line 1950) with this:

```python
def perform_create(self, serializer):
    # Get or create EmployeeProfile for the user
    employee, created = EmployeeProfile.objects.get_or_create(
        user=self.request.user,
        defaults={
            'display_name': self.request.user.username,
            'public_name': self.request.user.username,
        }
    )
    if created:
        print(f"Created EmployeeProfile for user: {self.request.user.email}")
    
    serializer.save(employee=employee)
```

## Quick Deployment Steps

1. SSH into your Digital Ocean server:
```bash
ssh root@64.225.122.101
```

2. Navigate to your project:
```bash
cd /path/to/your/backend/api
```

3. Edit the file:
```bash
nano obeeomaapp/views.py
```

4. Find the perform_create method (search for "def perform_create") and replace it with the code above

5. Restart your server:
```bash
sudo systemctl restart gunicorn
sudo systemctl restart nginx
```

## Alternative: One-liner fix
```bash
# Backup first
cp obeeomaapp/views.py obeeomaapp/views.py.backup

# Apply the fix using sed (run this on your server)
sed -i 's/employee = get_object_or_404(EmployeeProfile, user=self.request.user)/# Get or create EmployeeProfile for the user\n    employee, created = EmployeeProfile.objects.get_or_create(\n        user=self.request.user,\n        defaults={\n            '\''display_name'\'': self.request.user.username,\n            '\''public_name'\'': self.request.user.username,\n        }\n    )\n    if created:\n        print(f"Created EmployeeProfile for user: {self.request.user.email}")\n    \n    serializer.save(employee=employee)/g' obeeomaapp/views.py
```
