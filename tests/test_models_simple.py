"""
Simplified model tests that only test existing models
"""
from django.test import TestCase
from django.contrib.auth import get_user_model

User = get_user_model()

from obeeomaapp.models import (
    Employer, EmployeeInvitation, AuthenticationEvent, 
    SystemSetting, SystemStatus, MentalHealthAssessment,
    Department, PasswordResetToken, EmployeeProfile,
    Subscription, SubscriptionPlan
)


class BasicUserModelTest(TestCase):
    """Test User model"""
    
    def test_create_user(self):
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertTrue(user.check_password('testpass123'))
    
    def test_create_superuser(self):
        admin = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass123'
        )
        self.assertTrue(admin.is_superuser)
        self.assertTrue(admin.is_staff)


class BasicEmployerModelTest(TestCase):
    """Test Employer model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='employer1',
            email='employer@example.com',
            password='pass123'
        )
    
    def test_create_employer(self):
        employer = Employer.objects.create(
            user=self.user,
            company_name='Test Company',
            industry='Technology'
        )
        self.assertEqual(employer.company_name, 'Test Company')
        self.assertEqual(employer.user, self.user)


class BasicInvitationModelTest(TestCase):
    """Test EmployeeInvitation model"""
    
    def setUp(self):
        user = User.objects.create_user(
            username='employer1',
            email='employer@example.com',
            password='pass123'
        )
        self.employer = Employer.objects.create(
            user=user,
            company_name='Test Company'
        )
    
    def test_create_invitation(self):
        invitation = EmployeeInvitation.objects.create(
            employer=self.employer,
            email='employee@example.com'
        )
        self.assertEqual(invitation.email, 'employee@example.com')
        self.assertEqual(invitation.employer, self.employer)


class BasicMentalHealthAssessmentTest(TestCase):
    """Test MentalHealthAssessment model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='pass123'
        )
    
    def test_create_assessment(self):
        assessment = MentalHealthAssessment.objects.create(
            user=self.user,
            assessment_type='GAD-7',
            responses={'q1': 2, 'q2': 1}
        )
        self.assertEqual(assessment.assessment_type, 'GAD-7')
        self.assertEqual(assessment.user, self.user)
