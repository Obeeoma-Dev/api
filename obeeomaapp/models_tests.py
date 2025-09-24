from django.test import TestCase
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from datetime import date, timedelta
import decimal

from .models import (
    Organization,
    Client,
    AIRecommendation,
    HotlineActivity,
    PatientEngagement,
    Subscription,
    RecentActivity
)


class OrganizationModelTest(TestCase):
    #Tests for the Organization model 

    @classmethod
    def setUpTestData(cls):
        #Set up non-modified objects used by all test methods."
        cls.org = Organization.objects.create(name="")

    def test_organization_creation(self):
        self.assertIsInstance(self.org, Organization)
        self.assertEqual(self.org.name, "")
        self.assertTrue(self.org.is_active)
        self.assertIsNotNone(self.org.joined_date)

    def test_str_method(self):
        self.assertEqual(str(self.org), "")

    def test_name_is_unique(self):
        # Test that creating an organization with a duplicate name raises an error.
        with self.assertRaises(IntegrityError):
            Organization.objects.create(name="")

    def test_ordering(self):
        # Test that organizations are ordered by joined_date in descending order.
        org2 = Organization.objects.create(name="")
        # Manually set the time to be earlier to test ordering
        org2.joined_date = self.org.joined_date - timedelta(days=1)
        org2.save()
        self.assertEqual(Organization.objects.first().name, "")


class ClientModelTest(TestCase):
    # Tests for the Client model 

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="")
        cls.client = Client.objects.create(
            organization=cls.org,
            name="",
            email=""
        )

    def test_client_creation(self):
        self.assertEqual(self.client.organization.name, "")
        self.assertEqual(self.client.name, "")
        self.assertEqual(self.client.email, "")
        self.assertIsNotNone(self.client.joined_date)
        self.assertIsNotNone(self.client.last_active)

    def test_str_method(self):
        self.assertEqual(str(self.client), "")

    def test_email_is_unique(self):
        # Test that creating a client with a duplicate email raises an error
        with self.assertRaises(IntegrityError):
            Client.objects.create(
                organization=self.org,
                name="",
                email=""
            )

    def test_related_name(self):
        self.assertEqual(self.org.clients.count(), 1)
        self.assertEqual(self.org.clients.first().name, "")


class AIRecommendationModelTest(TestCase):
    # Tests for the AIRecommendation model 
    
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="")
        cls.rec = AIRecommendation.objects.create(
            organization=cls.org,
            title="",
            description="",
            effectiveness=95.50
        )

    def test_recommendation_creation(self):
        self.assertEqual(self.rec.title, "")
        self.assertEqual(self.rec.effectiveness, decimal.Decimal(""))
        self.assertEqual(self.rec.organization, self.org)

    def test_str_method(self):
        self.assertEqual(str(self.rec), "")

    def test_effectiveness_validators(self):
        """Test that effectiveness must be between 0 and 100."""
        with self.assertRaises(ValidationError):
            rec_low = AIRecommendation(organization=self.org, title="t", description="d", effectiveness=-0.01)
            rec_low.full_clean()
        
        with self.assertRaises(ValidationError):
            rec_high = AIRecommendation(organization=self.org, title="t", description="d", effectiveness=100.01)
            rec_high.full_clean()


class HotlineActivityModelTest(TestCase):
    """ Tests for the HotlineActivity model """

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="HealthCorp")
        cls.activity = HotlineActivity.objects.create(
            organization=cls.org,
            call_count=150,
            spike_percentage=15.25
        )

    def test_hotline_activity_creation(self):
        self.assertEqual(self.activity.call_count, 150)
        self.assertEqual(self.activity.spike_percentage, decimal.Decimal("15.25"))
        self.assertIsNotNone(self.activity.recorded_at)

    def test_call_count_default(self):
        """Test that call_count defaults to 0."""
        default_activity = HotlineActivity.objects.create(organization=self.org, spike_percentage=5)
        self.assertEqual(default_activity.call_count, 0)
    
    def test_verbose_name_plural(self):
        self.assertEqual(str(HotlineActivity._meta.verbose_name_plural), "Hotline Activities")

    def test_str_method(self):
        expected_str = f"Hotline Activity - {self.org.name} ({self.activity.recorded_at})"
        self.assertEqual(str(self.activity), expected_str)


class PatientEngagementModelTest(TestCase):
    """ Tests for the PatientEngagement model """

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="HealthCorp")
        cls.engagement_month = date(2025, 9, 1)
        cls.engagement = PatientEngagement.objects.create(
            organization=cls.org,
            engagement_rate=88.7,
            month=cls.engagement_month
        )

    def test_patient_engagement_creation(self):
        self.assertEqual(self.engagement.engagement_rate, decimal.Decimal("88.70"))
        self.assertEqual(self.engagement.month, self.engagement_month)
        self.assertIsNone(self.engagement.notes)

    def test_unique_together_constraint(self):
        """Test that an organization can only have one entry per month."""
        with self.assertRaises(IntegrityError):
            PatientEngagement.objects.create(
                organization=self.org,
                engagement_rate=90.0,
                month=self.engagement_month
            )
            
    def test_str_method(self):
        self.assertEqual(str(self.engagement), "HealthCorp - 2025-09-01")


class SubscriptionModelTest(TestCase):
    """ Tests for the Subscription model """

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="HealthCorp")
        cls.sub = Subscription.objects.create(
            organization=cls.org,
            plan="Premium",
            revenue=299.99,
            start_date=date.today()
        )

    def test_subscription_creation(self):
        self.assertEqual(self.sub.plan, "Premium")
        self.assertEqual(self.sub.revenue, decimal.Decimal("299.99"))
        self.assertTrue(self.sub.is_active)
        self.assertIsNone(self.sub.end_date)
    
    def test_plan_default(self):
        """Test that the plan defaults to 'Free'."""
        default_sub = Subscription.objects.create(organization=self.org, start_date=date.today())
        self.assertEqual(default_sub.plan, "Free")
        self.assertEqual(default_sub.revenue, decimal.Decimal("0.00"))

    def test_str_method(self):
        self.assertEqual(str(self.sub), "HealthCorp - Premium")


class RecentActivityModelTest(TestCase):
    """ Tests for the RecentActivity model """

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="HealthCorp")
        cls.activity = RecentActivity.objects.create(
            organization=cls.org,
            activity_type="New Organization",
            details="HealthCorp joined the platform."
        )

    def test_recent_activity_creation(self):
        self.assertEqual(self.activity.activity_type, "New Organization")
        self.assertEqual(self.activity.details, "HealthCorp joined the platform.")
        self.assertFalse(self.activity.is_important)
        self.assertIsNotNone(self.activity.timestamp)

    def test_str_method(self):
        self.assertEqual(str(self.activity), "New Organization - HealthCorp")

    def test_verbose_name_plural(self):
        self.assertEqual(str(RecentActivity._meta.verbose_name_plural), "Recent Activities")