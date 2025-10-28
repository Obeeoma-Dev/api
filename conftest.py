"""
Pytest configuration for Django tests
"""
import pytest


@pytest.fixture(scope='session')
def django_db_setup():
    """Setup test database"""
    pass
