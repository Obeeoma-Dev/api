#!/usr/bin/env python
import os
import django

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from django.db import connection

# Check what columns exist in the chatsession table
with connection.cursor() as cursor:
    cursor.execute("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'obeeomaapp_chatsession';
    """)
    columns = [row[0] for row in cursor.fetchall()]
    print("Columns in obeeomaapp_chatsession table:")
    for col in columns:
        print(f"  - {col}")
    
    # Check if last_message_at exists
    if 'last_message_at' in columns:
        print("\n✅ last_message_at column exists")
    else:
        print("\n❌ last_message_at column is MISSING")
