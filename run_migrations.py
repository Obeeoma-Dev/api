#!/usr/bin/env python
"""
Script to run Django migrations
"""
import os
import sys
import django

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

# Import Django management
from django.core.management import call_command

print("=" * 50)
print("Running Django Migrations")
print("=" * 50)
print()

try:
    print("Step 1: Making migrations...")
    call_command('makemigrations')
    print("✓ Migrations created successfully!")
    print()
    
    print("Step 2: Running migrations...")
    call_command('migrate')
    print("✓ Migrations applied successfully!")
    print()
    
    print("=" * 50)
    print("Migration Complete!")
    print("=" * 50)
    
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)
