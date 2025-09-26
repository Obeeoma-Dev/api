from django.test import TestCase
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from datetime import date, timedelta
import decimal 


from .models import (
    Organization,
    Client,
    AIManagement,
    HotlineActivity,
    ClientEngagement,
    Subscription,
    RecentActivity
)


class OrganizationModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Test Organization")

    def test_organization_creation(self):
        self.assertIsInstance(self.org, Organization)
        self.assertEqual(self.org.name, "Test Organization")
        self.assertTrue(self.org.is_active)
        self.assertIsNotNone(self.org.joined_date)

    def test_str_method(self):
        self.assertEqual(str(self.org), "Test Organization")


class ClientModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Test Organization")
        cls.client = Client.objects.create(
            organization=cls.org,
            name="Test Client",
            email="test@example.com"
        )

    def test_client_creation(self):
        self.assertEqual(self.client.organization.name, "Test Organization")
        self.assertEqual(self.client.name, "Test Client")
        self.assertEqual(self.client.email, "test@example.com")
        self.assertIsNotNone(self.client.joined_date)
        self.assertIsNotNone(self.client.last_active)


class AIManagementModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Test Organization")
        cls.ai_management = AIManagement.objects.create(
            organization=cls.org,
            title="Test Management",
            description="Test Description",
            effectiveness=95.50
        )

    def test_ai_management_creation(self):
        self.assertEqual(self.ai_management.title, "Test Management")
        self.assertEqual(float(self.ai_management.effectiveness), 95.50)
        self.assertEqual(self.ai_management.organization.name, "Test Organization")


class HotlineActivityModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Test Organization")
        cls.activity = HotlineActivity.objects.create(
            organization=cls.org,
            call_count=150,
            spike_percentage=15.25
        )

    def test_hotline_activity_creation(self):
        self.assertEqual(self.activity.call_count, 150)
        self.assertEqual(float(self.activity.spike_percentage), 15.25)
        self.assertIsNotNone(self.activity.recorded_at)


class ClientEngagementModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Test Organization")
        cls.engagement = ClientEngagement.objects.create(
            organization=cls.org,
            engagement_rate=88.7
        )

    def test_client_engagement_creation(self):
        self.assertEqual(float(self.engagement.engagement_rate), 88.7)
        self.assertEqual(self.engagement.organization.name, "Test Organization")


class SubscriptionModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Test Organization")
        cls.subscription = Subscription.objects.create(
            organization=cls.org,
            plan="Premium",
            revenue=299.99,
            start_date=date.today()
        )

    def test_subscription_creation(self):
        self.assertEqual(self.subscription.plan, "Premium")
        self.assertEqual(float(self.subscription.revenue), 299.99)
        self.assertEqual(self.subscription.organization.name, "Test Organization")


class RecentActivityModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Test Organization")
        cls.activity = RecentActivity.objects.create(
            organization=cls.org,
            activity_type="New Organization",
            details="New organization created"
        )

    def test_recent_activity_creation(self):
        self.assertEqual(self.activity.activity_type, "New Organization")
        self.assertEqual(self.activity.details, "New organization created")
        self.assertEqual(self.activity.organization.name, "Test Organization")
        self.assertIsNotNone(self.activity.timestamp)