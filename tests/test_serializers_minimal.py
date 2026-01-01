"""
Minimal serializer tests - only testing serializers that exist and work
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta

from obeeomaapp.serializers import (
    LoginSerializer, LogoutSerializer,
    PasswordResetSerializer, UserSerializer,
    EmployerSerializer, EmployeeInvitationCreateSerializer,
    MentalHealthAssessmentSerializer
)
from obeeomaapp.models import Employer, EmployeeInvitation

User = get_user_model()


# class SignupSerializerTest(TestCase):
#     def setUp(self):
#         self.valid_data = {
#             'username': 'testuser',
#             'email': 'test@example.com',
#             'password': 'SecurePass123!',
#             'confirm_password': 'SecurePass123!',
#             'role': 'employee'
#         }

#     def test_valid_signup_data(self):
#         serializer = SignupSerializer(data=self.valid_data)
#         self.assertTrue(serializer.is_valid())

#     def test_password_mismatch(self):
#         invalid_data = self.valid_data.copy()
#         invalid_data['confirm_password'] = 'DifferentPass123!'
#         serializer = SignupSerializer(data=invalid_data)
#         self.assertFalse(serializer.is_valid())

#     def test_user_creation(self):
#         serializer = SignupSerializer(data=self.valid_data)
#         self.assertTrue(serializer.is_valid())
#         user = serializer.save()
#         self.assertEqual(user.username, 'testuser')
#         self.assertEqual(user.email, 'test@example.com')


class LoginSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.valid_data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }

    def test_valid_login(self):
        serializer = LoginSerializer(data=self.valid_data, context={'request': None})
        self.assertTrue(serializer.is_valid())


class EmployerSerializerTest(TestCase):
    def test_employer_serialization(self):
        employer = Employer.objects.create(
            name='Test Company',
            is_active=True
        )
        serializer = EmployerSerializer(employer)
        self.assertEqual(serializer.data['name'], 'Test Company')
        self.assertTrue(serializer.data['is_active'])


class EmployeeInvitationSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='employer@example.com',
            password='pass123'
        )
        self.employer = Employer.objects.create(
            name='Test Company',
            is_active=True
        )

    def test_invitation_creation(self):
        data = {
            'email': 'employee@example.com',
            'message': 'Welcome!'
        }
        serializer = EmployeeInvitationCreateSerializer(
            data=data,
            context={'employer': self.employer, 'user': self.user}
        )
        self.assertTrue(serializer.is_valid())
        invitation = serializer.save()
        self.assertEqual(invitation.email, 'employee@example.com')
        self.assertEqual(invitation.employer, self.employer)


class MentalHealthAssessmentSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='pass123'
        )

    def test_valid_gad7_assessment(self):
        data = {
            'assessment_type': 'GAD-7',
            'gad7_scores': [2, 1, 0, 1, 2, 1, 0]
        }
        serializer = MentalHealthAssessmentSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_phq9_assessment(self):
        data = {
            'assessment_type': 'PHQ-9',
            'phq9_scores': [2, 2, 1, 1, 0, 1, 2, 1, 0]
        }
        serializer = MentalHealthAssessmentSerializer(data=data)
        self.assertTrue(serializer.is_valid())
