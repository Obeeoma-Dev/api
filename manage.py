"""Django's command-line utility for administrative tasks."""
import os
import sys
from dotenv import load_dotenv

# Load .env file and override any existing environment variables
load_dotenv(override=True)

def main():
    """Run administrative tasks."""
    # Force set to api.settings (override any existing value)
    os.environ['DJANGO_SETTINGS_MODULE'] = os.getenv('DJANGO_SETTINGS_MODULE', 'api.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()

def print_python_version():
    print(sys.version_info)
