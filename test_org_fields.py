import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from obeeomaapp.models import Organization

# Check if fields exist
print("Organization model fields:")
for field in Organization._meta.get_fields():
    print(f"  - {field.name}")

# Try to query
try:
    org = Organization.objects.first()
    if org:
        print(f"\nFirst organization: {org.organizationName}")
        print(f"  created_at: {org.created_at}")
        print(f"  updated_at: {org.updated_at}")
    else:
        print("\nNo organizations in database")
except Exception as e:
    print(f"\nError querying: {e}")
