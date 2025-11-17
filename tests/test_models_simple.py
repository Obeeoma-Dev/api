"""
Simplified model tests that only test existing models
"""
from django.test import TestCase
from django.contrib.auth import get_user_model

User = get_user_model()

from obeeomaapp.models import (
    Employer, EmployeeInvitation, Employee,
    MentalHealthAssessment, Department
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


class EmployerModelTest(TestCase):
    """Test Employer model"""
    
    def test_create_employer(self):
        employer = Employer.objects.create(
            name='Test Company',
            is_active=True
        )
        self.assertEqual(employer.name, 'Test Company')
        self.assertTrue(employer.is_active)


class EmployeeModelTest(TestCase):
    """Test Employee model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='employee1',
            email='employee@example.com',
            password='pass123'
        )
        self.employer = Employer.objects.create(
            name='Test Company',
            is_active=True
        )
    
    def test_create_employee(self):
        employee = Employee.objects.create(
            user=self.user,
            employer=self.employer,
            first_name='John',
            last_name='Doe',
            email='john.doe@example.com',
            status='active'
        )
        self.assertEqual(employee.first_name, 'John')
        self.assertEqual(employee.last_name, 'Doe')
        self.assertEqual(employee.name, 'John Doe')  # Test the property
        self.assertEqual(employee.employer, self.employer)


class InvitationModelTest(TestCase):
    """Test EmployeeInvitation model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='employer1',
            email='employer@example.com',
            password='pass123'
        )
        self.employer = Employer.objects.create(
            name='Test Company',
            is_active=True
        )
    
    def test_create_invitation(self):
        invitation = EmployeeInvitation.objects.create(
            employer=self.employer,
            email='employee@example.com',
            invited_by=self.user,
            token='test-token-123',
            message='Welcome to our team!'
        )
        self.assertEqual(invitation.email, 'employee@example.com')
        self.assertEqual(invitation.employer, self.employer)
        self.assertEqual(invitation.invited_by, self.user)
        self.assertFalse(invitation.accepted)


class MentalHealthAssessmentModelTest(TestCase):
    """Test MentalHealthAssessment model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='pass123'
        )
    
    def test_create_gad7_assessment(self):
        assessment = MentalHealthAssessment.objects.create(
            user=self.user,
            assessment_type='GAD-7',
            gad7_scores=[2, 1, 0, 1, 2, 1, 0]
        )
        self.assertEqual(assessment.assessment_type, 'GAD-7')
        self.assertEqual(assessment.user, self.user)
        self.assertEqual(len(assessment.gad7_scores), 7)
        self.assertEqual(assessment.gad7_total, 7)
    
    def test_create_phq9_assessment(self):
        assessment = MentalHealthAssessment.objects.create(
            user=self.user,
            assessment_type='PHQ-9',
            phq9_scores=[2, 2, 1, 1, 0, 1, 2, 1, 0]
        )
        self.assertEqual(assessment.assessment_type, 'PHQ-9')
        self.assertEqual(len(assessment.phq9_scores), 9)
        self.assertEqual(assessment.phq9_total, 10)


class DepartmentModelTest(TestCase):
    """Test Department model"""
    
    def setUp(self):
        self.employer = Employer.objects.create(
            name='Test Company',
            is_active=True
        )
    
    def test_create_department(self):
        department = Department.objects.create(
            employer=self.employer,
            name='Engineering'
        )
        self.assertEqual(department.name, 'Engineering')
        self.assertEqual(department.employer, self.employer)
