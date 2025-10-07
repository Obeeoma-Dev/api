from django.test import TestCase
from obeeomaapp.models import (
    Employer,
    Employee,
    AIManagement,
    HotlineActivity,
    EmployeeEngagement,
    Subscription,
    RecentActivity
)
from datetime import date


class EmployerModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        
        cls.employer = Employer.objects.create(name="Test Employer")

    def test_employer_creation(self):
        self.assertIsInstance(self.employer, Employer)
        self.assertEqual(self.employer.name, "Test Employer")
        self.assertTrue(self.employer.is_active)
        self.assertIsNotNone(self.employer.joined_date)

    def test_str_method(self):
        self.assertEqual(str(self.employer), "Test Employer")


class EmployeeModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.employer = Employer.objects.create(name="Test Employer")
        cls.employee = Employee.objects.create(
            employer=cls.employer,
            name="Test Employee",
            email="test@example.com"
        )

    def test_employee_creation(self):
        self.assertEqual(self.employee.employer.name, "Test Employer")
        self.assertEqual(self.employee.name, "Test Employee")
        self.assertEqual(self.employee.email, "test@example.com")
        self.assertIsNotNone(self.employee.joined_date)
        self.assertIsNotNone(self.employee.last_active)


class AIManagementModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.employer = Employer.objects.create(name="Test Employer")
        cls.ai_management = AIManagement.objects.create(
            employer=cls.employer,
            title="Test Management",
            description="Test Description",
            effectiveness=95.50
        )

    def test_ai_management_creation(self):
        self.assertEqual(self.ai_management.title, "Test Management")
        self.assertEqual(float(self.ai_management.effectiveness), 95.50)
        self.assertEqual(self.ai_management.employer.name, "Test Employer")


class HotlineActivityModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.employer = Employer.objects.create(name="Test Employer")
        cls.activity = HotlineActivity.objects.create(
            employer=cls.employer,
            call_count=150,
            spike_percentage=15.25
        )

    def test_hotline_activity_creation(self):
        self.assertEqual(self.activity.call_count, 150)
        self.assertEqual(float(self.activity.spike_percentage), 15.25)
        self.assertIsNotNone(self.activity.recorded_at)


class EmployeeEngagementModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.employer = Employer.objects.create(name="Test Employer")
        cls.engagement = EmployeeEngagement.objects.create(
            employer=cls.employer,
            engagement_rate=88.7,
            month=date.today()
        )

    def test_employee_engagement_creation(self):
        self.assertEqual(float(self.engagement.engagement_rate), 88.7)
        self.assertEqual(self.engagement.employer.name, "Test Employer")


class SubscriptionModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.employer = Employer.objects.create(name="Test Employer")
        cls.subscription = Subscription.objects.create(
            employer=cls.employer,
            plan="Premium",
            amount=299.99,  
            start_date=date.today()
        )

    def test_subscription_creation(self):
        self.assertEqual(self.subscription.plan, "Premium")
        self.assertEqual(float(self.subscription.amount), 299.99)
        self.assertEqual(self.subscription.employer.name, "Test Employer")


class RecentActivityModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.employer = Employer.objects.create(name="Test Employer")
        cls.activity = RecentActivity.objects.create(
            employer=cls.employer,
            activity_type="New Employer",
            details="New employer created"
        )

    def test_recent_activity_creation(self):
        self.assertEqual(self.activity.activity_type, "New Employer")
        self.assertEqual(self.activity.details, "New employer created")
        self.assertEqual(self.activity.employer.name, "Test Employer")
        self.assertIsNotNone(self.activity.timestamp)
