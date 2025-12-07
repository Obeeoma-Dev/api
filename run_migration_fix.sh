#!/bin/bash
# Script to run the migration on production server

echo "Running migration to remove old invitation token fields..."
python manage.py migrate obeeomaapp

echo ""
echo "Migration complete! You can now send invitations."
