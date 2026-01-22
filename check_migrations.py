#!/usr/bin/env python
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from django.db import connection
from django.db.migrations.executor import MigrationExecutor

def get_pending_migrations():
    executor = MigrationExecutor(connection)
    return executor.migration_plan(executor.loader.leaf_nodes())

print("Pending migrations:")
for migration, backwards in get_pending_migrations():
    print(f"  {migration.app_label}.{migration.name}")

# Check if achievement table exists
with connection.cursor() as cursor:
    cursor.execute("""
        SELECT tablename FROM pg_tables 
        WHERE schemaname = 'public' AND tablename = 'obeeomaapp_achievement';
    """)
    result = cursor.fetchone()
    if result:
        print("Achievement table exists")
    else:
        print("Achievement table does NOT exist")
