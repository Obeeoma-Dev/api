# tests_utils.py - Helper functions for tests
from django.contrib.auth import get_user_model
from model_bakery import baker
from datetime import datetime, timedelta
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from obeeomaapp.models import PSS10Assessment

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



User = get_user_model()

class PSS10AssessmentTests(APITestCase):

    def setUp(self):
        # Create two users to test ownership
        self.user1 = User.objects.create_user(
            username="user1",
            email="user1@example.com",
            password="pass12345"
        )
        self.user2 = User.objects.create_user(
            username="user2",
            email="user2@example.com",
            password="pass12345"
        )

        # Authenticate using force_authenticate for API tests
        self.client.force_authenticate(user=self.user1)

        # URL name according to your router (adjust if different)
        self.url = reverse("obeeomaapp:pss10-assessment-list")  # router_basename is: pss10-assessment

    def test_create_pss_assessment(self):
        """User can create an assessment and score/category auto-calc."""
        data = {
            "responses": [1, 2, 3, 2, 1, 2, 2, 1, 3, 1]  # Sum = 18 → "Moderate stress"
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["score"], 18)
        self.assertEqual(response.data["category"], "Moderate stress")
        self.assertEqual(response.data["user"], self.user1.id)

    def test_user_can_only_see_their_own_assessments(self):
        """User1 should not see assessments belonging to User2."""
        
        # Create an assessment for user2
        PSS10Assessment.objects.create(
            user=self.user2,
            responses=[1]*10,
            score=10,
            category="Low stress"
        )

        # Create an assessment for user1
        PSS10Assessment.objects.create(
            user=self.user1,
            responses=[2]*10,
            score=20,
            category="Moderate stress"
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # Only their own
        self.assertEqual(response.data[0]["user"], self.user1.id)

    def test_prevent_accessing_others_detail(self):
        """User cannot retrieve details of another user's record."""
        
        assessment = PSS10Assessment.objects.create(
            user=self.user2,
            responses=[1]*10,
            score=10,
            category="Low stress"
        )

        detail_url = reverse("obeeomaapp:pss10-assessment-detail", args=[assessment.id])
        response = self.client.get(detail_url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

from unittest.mock import patch

from obeeomaapp.models import PaymentMethod

User = get_user_model()


class UpdatePaymentMethodTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="testuser@example.com",
            password="pass12345"
        )
        # Create an employer for the payment method
        from obeeomaapp.models import Employer, Employee, Department
        self.employer = Employer.objects.create(name="Test Company")
        
        # Create a department
        self.department = Department.objects.create(
            employer=self.employer,
            name="Test Department"
        )
        
        # Associate user with employer through Employee
        self.employee = Employee.objects.create(
            user=self.user,
            employer=self.employer,
            department=self.department,
            first_name="Test",
            last_name="User",
            email="testuser@example.com"
        )
        
        # Authenticate using force_authenticate for API tests
        self.client.force_authenticate(user=self.user)
        # Adjust to your router basename
        self.url = reverse("obeeomaapp:payment-method-list")

    def test_create_new_payment_method(self):
        data = {
            "token_id": "tok_123",
            "card_last_four": "4242",
            "card_type": "Visa"
        }
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("message", response.data)

        payment_method = PaymentMethod.objects.get(user=self.user)
        self.assertEqual(payment_method.last_four_digits, "4242")

    def test_update_existing_payment_method(self):
        PaymentMethod.objects.create(
            user=self.user,
            employer=self.employer,
            token_id="tok_old",
            last_four_digits="1111",
            card_type="MasterCard",
            expiry_month=12,
            expiry_year=2024,
            is_default=True
        )

        data = {
            "token_id": "tok_new",
            "card_last_four": "2222",
            "card_type": "Visa"
        }
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("message", response.data)

        payment_method = PaymentMethod.objects.get(user=self.user)
        self.assertEqual(payment_method.token_id, "tok_new")
        self.assertEqual(payment_method.last_four_digits, "2222")

    def test_invalid_data_returns_400(self):
        data = {"card_type": "Visa"}  # Missing token_id
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("token_id", response.data)

    def test_database_error_returns_500(self):
        data = {
            "token_id": "tok_123",
            "card_last_four": "4242",
            "card_type": "Visa"
        }
        with patch("obeeomaapp.models.PaymentMethod.objects.update_or_create") as mock_update:
            mock_update.side_effect = Exception("DB error")
            response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn("detail", response.data)

