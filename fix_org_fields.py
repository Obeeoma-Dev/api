import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from django.db import connection

# Add the columns
with connection.cursor() as cursor:
    try:
        # Add created_at column
        cursor.execute("""
            ALTER TABLE obeeomaapp_organization 
            ADD COLUMN created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL;
        """)
        print("✅ Added created_at column")
    except Exception as e:
        print(f"❌ Error adding created_at: {e}")
    
    try:
        # Add updated_at column
        cursor.execute("""
            ALTER TABLE obeeomaapp_organization 
            ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL;
        """)
        print("✅ Added updated_at column")
    except Exception as e:
        print(f"❌ Error adding updated_at: {e}")

print("\n✅ Done! Testing...")

# Test it
from obeeomaapp.models import Organization
org = Organization.objects.first()
if org:
    print(f"\nOrganization: {org.organizationName}")
    print(f"  created_at: {org.created_at}")
    print(f"  updated_at: {org.updated_at}")
else:
    print("\nNo organizations found in database")
