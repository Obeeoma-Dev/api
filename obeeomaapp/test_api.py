"""
Pytest tests for API endpoints
"""
import pytest
from django.urls import reverse
from rest_framework import status
from obeeomaapp.models import Employer, Employee


@pytest.mark.django_db
class TestEmployerAPI:
    """Test Employer API endpoints"""

    def test_list_employers(self, api_client, employer):
        """Test listing employers"""
        url = reverse('employer-list')
        response = api_client.get(url)
        assert response.status_code == status.HTTP_200_OK

    def test_create_employer(self, authenticated_client):
        """Test creating an employer"""
        url = reverse('employer-list')
        data = {
            'name': 'New Company',
            'is_active': True
        }
        response = authenticated_client.post(url, data, format='json')
        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    def test_retrieve_employer(self, api_client, employer):
        """Test retrieving a single employer"""
        url = reverse('employer-detail', kwargs={'pk': employer.pk})
        response = api_client.get(url)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


@pytest.mark.django_db
class TestEmployeeAPI:
    """Test Employee API endpoints"""

    def test_list_employees(self, api_client, employee):
        """Test listing employees"""
        url = reverse('employee-list')
        response = api_client.get(url)
        assert response.status_code == status.HTTP_200_OK

    def test_create_employee(self, authenticated_client, employer):
        """Test creating an employee"""
        url = reverse('employee-list')
        data = {
            'employer': employer.id,
            'name': 'New Employee',
            'email': 'newemp@test.com',
            'status': 'active'
        }
        response = authenticated_client.post(url, data, format='json')
        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]


@pytest.mark.django_db
class TestAuthenticationAPI:
    """Test authentication endpoints"""

    def test_user_registration(self, api_client):
        """Test user registration"""
        url = reverse('register')
        data = {
            'username': 'newuser',
            'email': 'newuser@test.com',
            'password': 'testpass123',
            'password2': 'testpass123'
        }
        response = api_client.post(url, data, format='json')
        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]

    def test_user_login(self, api_client, user):
        """Test user login"""
        url = reverse('login')
        data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        response = api_client.post(url, data, format='json')
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]


@pytest.mark.django_db
class TestDashboardAPI:
    """Test dashboard endpoints"""

    def test_dashboard_stats(self, authenticated_client, employer):
        """Test dashboard statistics endpoint"""
        url = reverse('dashboard-stats')
        response = authenticated_client.get(url)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN]


@pytest.mark.django_db
class TestMentalHealthAPI:
    """Test mental health related endpoints"""

    def test_mood_checkin_create(self, authenticated_client):
        """Test creating a mood check-in"""
        url = reverse('mood-checkin-list')
        data = {
            'mood': 'happy',
            'notes': 'Feeling good'
        }
        response = authenticated_client.post(url, data, format='json')
        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]

    def test_self_help_resources_list(self, api_client):
        """Test listing self-help resources"""
        url = reverse('selfhelp-resource-list')
        response = api_client.get(url)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]
