# tests_urls.py
from django.test import TestCase
from django.urls import reverse, resolve
from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model
from obeeomaapp.models import Employer, Employee, EmployeeProfile
from obeeomaapp.views import *

User = get_user_model()


class URLTests(APITestCase):
    def setUp(self):
        # Create test users
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
        self.regular_user = User.objects.create_user(
            username='regular',
            email='regular@example.com',
            password='regularpass123',
            is_staff=False
        )
        self.employer = Employer.objects.create(name='Test Company')
        self.employee_profile = EmployeeProfile.objects.create(
            user=self.regular_user,
            organization='Test Org',
            role='Developer'
        )

    def test_home_url(self):
        """Test home URL resolves correctly"""
        url = reverse('obeeomaapp:home')
        self.assertEqual(url, '/')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_email_config_debug_url(self):
        """Test email config debug URL"""
        url = reverse('obeeomaapp:email-config-check')
        self.assertEqual(url, '/debug/email-config/')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class AuthenticationURLTests(APITestCase):
    def test_auth_urls(self):
        """Test all authentication URLs"""
        # Signup
        # url = reverse('obeeomaapp:signup')
        # self.assertEqual(url, '/auth/signup/')
        # self.assertEqual(resolve(url).func.view_class, SignupView)

        # Login
        url = reverse('obeeomaapp:login')
        self.assertEqual(url, '/auth/login/')
        self.assertEqual(resolve(url).func.view_class, LoginView)

        # Logout
        url = reverse('obeeomaapp:logout')
        self.assertEqual(url, '/auth/logout/')
        self.assertEqual(resolve(url).func.view_class, LogoutView)

        # Password Reset
        url = reverse('obeeomaapp:password-reset')
        self.assertEqual(url, '/auth/reset-password/')
        self.assertEqual(resolve(url).func.view_class, PasswordResetView)

        # Password Reset Confirm
        url = reverse('obeeomaapp:password-reset-confirm')
        self.assertEqual(url, '/auth/reset-password/confirm/')
        self.assertEqual(resolve(url).func.view_class, PasswordResetConfirmView)

        # Password Change
        url = reverse('obeeomaapp:password-change')
        self.assertEqual(url, '/auth/change-password/')
        self.assertEqual(resolve(url).func.view_class, PasswordChangeView)

        # Invitation Acceptance
        url = reverse('obeeomaapp:accept-invite')
        self.assertEqual(url, '/auth/accept-invite/')
        self.assertEqual(resolve(url).func.view_class, InvitationAcceptView)

    def test_jwt_urls(self):
        """Test JWT authentication URLs"""
        # Token Obtain
        url = reverse('obeeomaapp:token_obtain_pair')
        self.assertEqual(url, '/auth/token/')

        # Token Refresh
        url = reverse('obeeomaapp:token_refresh')
        self.assertEqual(url, '/auth/token/refresh/')

        # Token Verify
        url = reverse('obeeomaapp:token_verify')
        self.assertEqual(url, '/auth/token/verify/')


class DashboardURLTests(APITestCase):
    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
        self.client.force_authenticate(user=self.admin_user)

    def test_dashboard_urls(self):
        """Test dashboard URLs resolve correctly"""
        urls = [
            ('overview', '/dashboard/overview/'),
            ('trends', '/dashboard/trends/'),
            ('employee-engagement', '/dashboard/employee-engagement/'),
            ('features-usage', '/dashboard/features-usage/'),
            ('billing', '/dashboard/billing/'),
            ('invites', '/dashboard/invites/'),
            ('users', '/dashboard/users/'),
            ('reports', '/dashboard/reports/'),
            ('crisis-insights', '/dashboard/crisis-insights/'),
        ]

        for name, expected_url in urls:
            url = reverse(f'obeeomaapp:{name}')
            self.assertEqual(url, expected_url)

    def test_subscription_management_urls(self):
        """Test subscription management URLs"""
        # Current Subscription
        url = reverse('obeeomaapp:current-subscription')
        self.assertEqual(url, '/dashboard/subscriptions/current/')

        # Available Plans
        url = reverse('obeeomaapp:available-plans')
        self.assertEqual(url, '/dashboard/subscriptions/plans/')

        # Billing History
        url = reverse('obeeomaapp:billing-history')
        self.assertEqual(url, '/dashboard/subscriptions/billing-history/')


class EmployeeURLTests(APITestCase):
    def setUp(self):
        self.regular_user = User.objects.create_user(
            username='regular',
            email='regular@example.com',
            password='regularpass123'
        )
        self.client.force_authenticate(user=self.regular_user)

    def test_employee_profile_urls(self):
        """Test employee profile URLs"""
        urls = [
            ('employee-profile', '/employee/profile/'),
            ('avatar-profile', '/employee/avatar/'),
            ('wellness-hub', '/employee/wellness/'),
            ('mood-checkin', '/employee/mood-checkin/'),
            ('assessment-results', '/employee/assessments/'),
            ('crisis-trigger', '/employee/crisis/'),
            ('notifications', '/employee/notifications/'),
            ('engagement-tracker', '/employee/engagement/'),
            ('feedback', '/employee/feedback/'),
            ('chat-sessions', '/sana/sessions/'),
            ('recommendation-log', '/employee/recommendations/'),
        ]

        for name, expected_url in urls:
            url = reverse(f'obeeomaapp:{name}')
            self.assertEqual(url, expected_url)

    def test_resource_urls(self):
        """Test resource URLs"""
        # Self-help resources
        url = reverse('obeeomaapp:self-help-resources')
        self.assertEqual(url, '/resources/self-help/')

        # Educational resources
        url = reverse('obeeomaapp:educational-resources')
        self.assertEqual(url, '/resources/educational/')

    def test_chat_message_url(self):
        """Test chat message URL with session ID"""
        url = reverse('obeeomaapp:chat-messages', kwargs={'session_id': 1})
        self.assertEqual(url, '/sana/sessions/1/messages/')


class RouterURLTests(APITestCase):
    def test_router_urls(self):
        """Test that router URLs are properly configured"""
        # Mental Health Assessments
        url = reverse('obeeomaapp:mental-health-assessment-list')
        self.assertEqual(url, '/mental-health/assessments/')

        # Employers
        url = reverse('obeeomaapp:employer-list')
        self.assertEqual(url, '/employers/')

        # Badges
        url = reverse('obeeomaapp:my-badges-list')
        self.assertEqual(url, '/me/badges/')

        # Streaks
        url = reverse('obeeomaapp:my-streaks-list')
        self.assertEqual(url, '/me/streaks/')

        # Progress
        url = reverse('obeeomaapp:progress-list')
        self.assertEqual(url, '/progress/')

        # Resource Categories
        url = reverse('obeeomaapp:resource-category-list')
        self.assertEqual(url, '/resource-categories/')

        # Videos
        url = reverse('obeeomaapp:videos-list')
        self.assertEqual(url, '/videos/')

        # Video Interactions
        url = reverse('obeeomaapp:video-interactions-list')
        self.assertEqual(url, '/video-interactions/')

    def test_dashboard_router_urls(self):
        """Test dashboard router URLs"""
        # Organization Overview
        url = reverse('obeeomaapp:organization-overview-list')
        self.assertEqual(url, '/dashboard/organization-overview/')

        # Employee Management
        url = reverse('obeeomaapp:employee-management-list')
        self.assertEqual(url, '/dashboard/employees/')

        # Department Management
        url = reverse('obeeomaapp:department-management-list')
        self.assertEqual(url, '/dashboard/departments/')

        # Subscription Management
        url = reverse('obeeomaapp:subscription-management-list')
        self.assertEqual(url, '/dashboard/subscriptions/')

        # Wellness Reports
        url = reverse('obeeomaapp:wellness-reports-list')
        self.assertEqual(url, '/dashboard/wellness-reports/')

        # Organization Settings
        url = reverse('obeeomaapp:organization-settings-list')
        self.assertEqual(url, '/dashboard/settings/')

    def test_system_admin_router_urls(self):
        """Test system admin router URLs"""
        # System Admin Overview
        url = reverse('obeeomaapp:system-admin-overview-list')
        self.assertEqual(url, '/admin/overview/')

        # Organizations Management
        url = reverse('obeeomaapp:organizations-management-list')
        self.assertEqual(url, '/admin/organizations/')

        # Hotline Activity
        url = reverse('obeeomaapp:hotline-activity-list')
        self.assertEqual(url, '/admin/hotline-activity/')

        # AI Management
        url = reverse('obeeomaapp:ai-management-list')
        self.assertEqual(url, '/admin/ai-management/')

        # Client Engagement
        url = reverse('obeeomaapp:client-engagement-list')
        self.assertEqual(url, '/admin/client-engagement/')

        # Reports Analytics
        url = reverse('obeeomaapp:reports-analytics-list')
        self.assertEqual(url, '/admin/reports-analytics/')

        # System Settings
        url = reverse('obeeomaapp:system-settings-list')
        self.assertEqual(url, '/admin/system-settings/')


class SystemAdminURLTests(APITestCase):
    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
        self.client.force_authenticate(user=self.admin_user)

    def test_system_admin_special_urls(self):
        """Test system admin special action URLs"""
        # Organizations Growth Chart
        url = reverse('obeeomaapp:organizations-growth-chart')
        self.assertEqual(url, '/admin/organizations/growth-chart/')

        # Client Distribution
        url = reverse('obeeomaapp:organizations-client-distribution')
        self.assertEqual(url, '/admin/organizations/client-distribution/')

        # Feature Flags by Category
        url = reverse('obeeomaapp:feature-flags-by-category')
        self.assertEqual(url, '/admin/feature-flags/by-category/')


class APIEndpointsFunctionalTests(APITestCase):
    """Functional tests to ensure endpoints actually work"""

    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
        self.regular_user = User.objects.create_user(
            username='regular',
            email='regular@example.com',
            password='regularpass123'
        )

    def test_authentication_endpoints_accessible(self):
        """Test that authentication endpoints are publicly accessible"""
        public_endpoints = [
            reverse('obeeomaapp:signup'),
            reverse('obeeomaapp:login'),
            reverse('obeeomaapp:password-reset'),
            reverse('obeeomaapp:accept-invite'),
        ]

        for url in public_endpoints:
            response = self.client.get(url) if url != reverse('obeeomaapp:signup') else self.client.post(url, {})
            # Most will return 400/405 for bad data, but should not return 404 or 403
            self.assertNotIn(response.status_code, [404, 403])

    def test_protected_endpoints_require_authentication(self):
        """Test that protected endpoints require authentication"""
        protected_endpoints = [
            reverse('obeeomaapp:employee-profile'),
            reverse('obeeomaapp:overview'),
            reverse('obeeomaapp:progress-list'),
        ]

        for url in protected_endpoints:
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_admin_endpoints_require_admin_permissions(self):
        """Test that admin endpoints require staff permissions"""
        # Authenticate as regular user
        self.client.force_authenticate(user=self.regular_user)

        admin_endpoints = [
            reverse('obeeomaapp:overview'),
            reverse('obeeomaapp:employer-list'),
            reverse('obeeomaapp:system-admin-overview-list'),
        ]

        for url in admin_endpoints:
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_employee_endpoints_work_for_authenticated_users(self):
        """Test that employee endpoints work for authenticated regular users"""
        self.client.force_authenticate(user=self.regular_user)

        employee_endpoints = [
            reverse('obeeomaapp:employee-profile'),
            reverse('obeeomaapp:mental-health-assessment-list'),
            reverse('obeeomaapp:my-badges-list'),
        ]

        for url in employee_endpoints:
            response = self.client.get(url)
            self.assertIn(response.status_code, [200, 404])  # 404 if no data, but endpoint exists

    def test_api_documentation_urls(self):
        """Test API documentation URLs"""
        docs_urls = [
            reverse('obeeomaapp:schema'),
            reverse('obeeomaapp:swagger-ui'),
            reverse('obeeomaapp:schema-swagger-ui'),
            reverse('obeeomaapp:schema-redoc'),
        ]

        for url in docs_urls:
            response = self.client.get(url)
            self.assertIn(response.status_code, [200, 302])  # 302 for redirects


class URLReverseTests(TestCase):
    """Test URL reverse lookups work correctly"""

    def test_all_named_urls_can_be_reversed(self):
        """Test that all named URLs can be successfully reversed"""
        url_names = [
            'home',
            'email-config-check',
            'signup',
            'login',
            'logout',
            'password-reset',
            'password-reset-confirm',
            'password-change',
            'overview',
            'trends',
            'employee-engagement',
            'features-usage',
            'billing',
            'invites',
            'users',
            'reports',
            'crisis-insights',
            'current-subscription',
            'available-plans',
            'billing-history',
            'organizations-growth-chart',
            'organizations-client-distribution',
            'feature-flags-by-category',
            'employee-profile',
            'avatar-profile',
            'wellness-hub',
            'mood-checkin',
            'assessment-results',
            'self-help-resources',
            'educational-resources',
            'crisis-trigger',
            'notifications',
            'engagement-tracker',
            'feedback',
            'chat-sessions',
            'chat-messages',
            'recommendation-log',
            'accept-invite',
            'token_obtain_pair',
            'token_refresh',
            'token_verify',
            'schema',
            'swagger-ui',
            'schema-swagger-ui',
            'schema-redoc',
        ]

        for name in url_names:
            try:
                url = reverse(f'obeeomaapp:{name}')
                self.assertIsNotNone(url)
            except Exception as e:
                self.fail(f"Failed to reverse URL '{name}': {e}")


class URLPatternTests(TestCase):
    """Test URL patterns match expected paths"""

    def test_url_patterns(self):
        """Test that URL patterns match expected paths"""
        patterns = [
            ('/', 'home'),
            ('/debug/email-config/', 'email-config-check'),
            ('/auth/signup/', 'signup'),
            ('/auth/login/', 'login'),
            ('/auth/logout/', 'logout'),
            ('/auth/reset-password/', 'password-reset'),
            ('/auth/reset-password/confirm/', 'password-reset-confirm'),
            ('/auth/change-password/', 'password-change'),
            ('/dashboard/overview/', 'overview'),
            ('/employee/profile/', 'employee-profile'),
            ('/sana/sessions/1/messages/', 'chat-messages'),
        ]

        for path, name in patterns:
           # For URLs that need session_id:
            try:
                reversed_url = reverse(f'obeeomaapp:{name}')
            except Exception as e:
                # If it needs session_id, try with parameter
                if 'session_id' in str(e):
                    reversed_url = reverse(f'obeeomaapp:{name}', kwargs={'session_id': 1})
                else:
                    raise e

class MentalHealthAssessmentURLTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)

    def test_mental_health_assessment_urls(self):
        """Test mental health assessment custom action URLs"""
        # Submit assessment action
        url = reverse('obeeomaapp:mental-health-assessment-submit-assessment')
        self.assertEqual(url, '/mental-health/assessments/submit-assessment/')

        # My results action
        url = reverse('obeeomaapp:mental-health-assessment-my-results')
        self.assertEqual(url, '/mental-health/assessments/my-results/')

    def test_mental_health_assessment_detail_action(self):
        """Test mental health assessment detail action URL"""
        # This would typically require an instance ID
        # We test that the pattern exists
        assessment = MentalHealthAssessment.objects.create(
            user=self.user,
            assessment_type='GAD-7',
            gad7_scores=[1, 2, 1, 1, 0, 1, 2]
        )
        
        # Detailed results for specific assessment
        url = reverse('obeeomaapp:mental-health-assessment-detailed-results', kwargs={'pk': assessment.id})
        self.assertEqual(url, f'/mental-health/assessments/{assessment.id}/detailed-results/')


class EducationalVideoURLTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)

    def test_educational_video_action_urls(self):
        """Test educational video custom action URLs"""
        # Mark helpful action
        url = reverse('obeeomaapp:videos-mark-helpful', kwargs={'pk': 1})
        self.assertEqual(url, '/videos/1/mark_helpful/')

        # Save video action
        url = reverse('obeeomaapp:videos-save-video', kwargs={'pk': 1})
        self.assertEqual(url, '/videos/1/save_video/')


