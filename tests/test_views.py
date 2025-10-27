# tests_utils.py - Helper functions for tests
from django.contrib.auth import get_user_model
from model_bakery import baker
from datetime import datetime, timedelta

User = get_user_model()

def create_test_user(**kwargs):
    """Create a test user with default values"""
    defaults = {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'testpass123',
    }
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)

def create_test_employer(**kwargs):
    """Create a test employer"""
    return baker.make('Employer', **kwargs)

def create_test_employee(employer, **kwargs):
    """Create a test employee"""
    defaults = {
        'name': 'Test Employee',
        'email': 'employee@example.com',
        'employer': employer,
    }
    defaults.update(kwargs)
    return baker.make('Employee', **defaults)

def authenticate_client(client, user):
    """Authenticate a test client with a user"""
    client.force_authenticate(user=user)
    return client