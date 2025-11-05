# scripts/run_clean_duplicates.py
# Run with: python scripts/run_clean_duplicates.py

import os
import sys

# Ensure project root is on path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Set settings module (adjust if your settings module path differs)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')

import django
django.setup()

# Execute the script
script_path = os.path.join(os.path.dirname(__file__), 'clean_duplicates.py')
with open(script_path, 'r', encoding='utf-8') as f:
    code = f.read()

# Run the script in this process
exec(compile(code, script_path, 'exec'))



