#!/usr/bin/env python
import os
import django

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'obeeomaapp.settings')
django.setup()

from obeeomaapp.models import Employer, Employee

# Check counts
org_count = Employer.objects.count()
client_count = Employee.objects.count()

print(f"Organizations in database: {org_count}")
print(f"Clients in database: {client_count}")

# Show some details if there are organizations
if org_count > 0:
    print("\nRecent organizations:")
    for org in Employer.objects.all()[:5]:
        print(f"- {org.name} (ID: {org.id})")

if client_count > 0:
    print("\nRecent clients:")
    for client in Employee.objects.all()[:5]:
        print(f"- {client.user.email if client.user else 'Unknown'} (ID: {client.id})")
