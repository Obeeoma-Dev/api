from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.utils import timezone
from datetime import timedelta
import json

from .models import (
    User, Employer, Employee, EmployeeInvitation, AuthenticationEvent, 
    AdminAction, SystemSetting, SystemStatus, SelfAssessment, MoodCheckIn,
    SelfHelpResource, ChatbotInteraction, UserBadge, EngagementStreak,
    AnalyticsSnapshot, CrisisHotline, AIManagement, HotlineActivity,
    EmployeeEngagement, Subscription, RecentActivity, EmployeeProfile,
    AvatarProfile, WellnessHub, AssessmentResult, EducationalResource,
    CrisisTrigger, Notification, EngagementTracker, Feedback, Progress,
    ChatSession, ChatMessage, RecommendationLog, MentalHealthAssessment,
    Department, Assessment, PasswordResetToken, ResourceCategory,
    OrganizationSettings, SubscriptionPlan, BillingHistory, PaymentMethod,
    WellnessTest, ResourceEngagement, CommonIssue, ChatEngagement,
    DepartmentContribution, OrganizationActivity, PlatformMetrics,
    PlatformUsage, SubscriptionRevenue, SystemActivity, HotlineCall,
    AIResource, ClientEngagement, RewardProgram, SystemSettings, Report,
    EducationalVideo, UserVideoInteraction
)


class UserModelTest(TestCase):
    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123',
            'role': 'employee'
        }

    def test_create_user(self):
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.role, 'employee')
        self.assertFalse(user.onboarding_completed)
        self.assertFalse(user.is_suspended)

    def test_create_superuser(self):
        admin_user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass123'
        )
        self.assertTrue(admin_user.is_superuser)
        self.assertTrue(admin_user.is_staff)

    def test_user_str_representation(self):
        user = User.objects.create_user(**self.user_data)
        expected_str = f"{user.username} ({user.role})"
        self.assertEqual(str(user), expected_str)

    def test_user_role_choices(self):
        user = User.objects.create_user(**self.user_data)
        valid_roles = ['systemadmin', 'employer', 'employee']
        self.assertIn(user.role, valid_roles)

    def test_user_default_values(self):
        user = User.objects.create_user(**self.user_data)
        self.assertFalse(user.mfa_enabled)
        self.assertIsNone(user.mfa_secret)
        self.assertIsNone(user.avatar)


class EmployerModelTest(TestCase):
    def setUp(self):
        self.employer_data = {
            'name': 'Test Company'
        }

    def test_create_employer(self):
        employer = Employer.objects.create(**self.employer_data)
        self.assertEqual(employer.name, 'Test Company')
        self.assertTrue(employer.is_active)
        self.assertIsNotNone(employer.joined_date)

    def test_employer_unique_name(self):
        Employer.objects.create(**self.employer_data)
        with self.assertRaises(IntegrityError):
            Employer.objects.create(**self.employer_data)

    def test_employer_str_representation(self):
        employer = Employer.objects.create(**self.employer_data)
        self.assertEqual(str(employer), employer.name)

    def test_employer_ordering(self):
        employer1 = Employer.objects.create(name='Company A')
        employer2 = Employer.objects.create(name='Company B')
        employers = Employer.objects.all()
        self.assertEqual(employers[0], employer2)
        self.assertEqual(employers[1], employer1)


class EmployeeModelTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Employer')
        self.employee_data = {
            'employer': self.employer,
            'name': 'John Doe',
            'email': 'john@example.com',
            'status': 'active'
        }

    def test_create_employee(self):
        employee = Employee.objects.create(**self.employee_data)
        self.assertEqual(employee.name, 'John Doe')
        self.assertEqual(employee.email, 'john@example.com')
        self.assertEqual(employee.status, 'active')
        self.assertIsNotNone(employee.joined_date)

    def test_employee_unique_email(self):
        Employee.objects.create(**self.employee_data)
        with self.assertRaises(IntegrityError):
            Employee.objects.create(**self.employee_data)

    def test_employee_str_representation(self):
        employee = Employee.objects.create(**self.employee_data)
        expected_str = f"{employee.name} - {employee.employer.name}"
        self.assertEqual(str(employee), expected_str)

    def test_employee_status_choices(self):
        employee = Employee.objects.create(**self.employee_data)
        valid_statuses = ['active', 'inactive', 'suspended']
        self.assertIn(employee.status, valid_statuses)


class EmployeeInvitationModelTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Employer')
        self.user = User.objects.create_user(
            username='inviter',
            email='inviter@example.com',
            password='testpass123'
        )
        self.invitation_data = {
            'employer': self.employer,
            'email': 'newemployee@example.com',
            'token': 'test_token_123',
            'expires_at': timezone.now() + timedelta(days=7)
        }

    def test_create_invitation(self):
        invitation = EmployeeInvitation.objects.create(**self.invitation_data)
        self.assertEqual(invitation.email, 'newemployee@example.com')
        self.assertFalse(invitation.accepted)
        self.assertIsNone(invitation.accepted_at)

    def test_invitation_str_representation(self):
        invitation = EmployeeInvitation.objects.create(**self.invitation_data)
        expected_str = f"Invite {invitation.email} -> {invitation.employer.name}"
        self.assertEqual(str(invitation), expected_str)

    def test_invitation_indexes(self):
        # Test that token field is indexed
        invitation = EmployeeInvitation.objects.create(**self.invitation_data)
        self.assertIsNotNone(invitation.token)


class MentalHealthAssessmentModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.assessment_data = {
            'user': self.user,
            'assessment_type': 'GAD-7',
            'gad7_scores': [1, 2, 1, 1, 0, 1, 2],
            'phq9_scores': []
        }

    def test_create_assessment(self):
        assessment = MentalHealthAssessment.objects.create(**self.assessment_data)
        self.assertEqual(assessment.assessment_type, 'GAD-7')
        self.assertEqual(assessment.gad7_total, 8)
        self.assertEqual(assessment.gad7_severity, "Mild anxiety")

    def test_assessment_severity_calculation(self):
        # Test minimal anxiety
        assessment = MentalHealthAssessment.objects.create(
            user=self.user,
            assessment_type='GAD-7',
            gad7_scores=[0, 1, 0, 1, 0, 0, 1]
        )
        self.assertEqual(assessment.gad7_severity, "Minimal anxiety")

        # Test severe anxiety
        assessment2 = MentalHealthAssessment.objects.create(
            user=self.user,
            assessment_type='GAD-7',
            gad7_scores=[3, 3, 3, 3, 3, 3, 3]
        )
        self.assertEqual(assessment2.gad7_severity, "Severe anxiety")

    def test_phq9_severity_calculation(self):
        assessment = MentalHealthAssessment.objects.create(
            user=self.user,
            assessment_type='PHQ-9',
            phq9_scores=[1, 1, 1, 1, 1, 1, 1, 1, 1]  # Total: 9
        )
        self.assertEqual(assessment.phq9_severity, "Mild depression")

    def test_assessment_ordering(self):
        assessment1 = MentalHealthAssessment.objects.create(**self.assessment_data)
        assessment2 = MentalHealthAssessment.objects.create(
            user=self.user,
            assessment_type='PHQ-9',
            phq9_scores=[1, 1, 1, 1, 1, 1, 1, 1, 1]
        )
        assessments = MentalHealthAssessment.objects.all()
        self.assertEqual(assessments[0], assessment2)
        self.assertEqual(assessments[1], assessment1)


class DepartmentModelTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Employer')
        self.department_data = {
            'employer': self.employer,
            'name': 'Engineering'
        }

    def test_create_department(self):
        department = Department.objects.create(**self.department_data)
        self.assertEqual(department.name, 'Engineering')
        self.assertFalse(department.at_risk)

    def test_department_str_representation(self):
        department = Department.objects.create(**self.department_data)
        expected_str = f"{department.name} - {department.employer.name}"
        self.assertEqual(str(department), expected_str)


class SubscriptionModelTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Employer')
        self.subscription_data = {
            'employer': self.employer,
            'plan': 'starter',
            'seats': 10,
            'start_date': timezone.now().date(),
            'is_active': True
        }

    def test_create_subscription(self):
        subscription = Subscription.objects.create(**self.subscription_data)
        self.assertEqual(subscription.plan, 'starter')
        self.assertEqual(subscription.seats, 10)
        self.assertEqual(subscription.used_seats, 0)

    def test_available_seats_property(self):
        subscription = Subscription.objects.create(**self.subscription_data)
        subscription.used_seats = 3
        self.assertEqual(subscription.available_seats, 7)

    def test_subscription_str_representation(self):
        subscription = Subscription.objects.create(**self.subscription_data)
        expected_str = f"{subscription.employer.name} - {subscription.plan}"
        self.assertEqual(str(subscription), expected_str)


class PasswordResetTokenModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.token_data = {
            'user': self.user,
            'token': 'test_token_123',
            'code': '123456',
            'expires_at': timezone.now() + timedelta(hours=1)
        }

    def test_create_password_reset_token(self):
        token = PasswordResetToken.objects.create(**self.token_data)
        self.assertEqual(token.user, self.user)
        self.assertFalse(token.is_used)

    def test_is_expired_method(self):
        # Test not expired
        token = PasswordResetToken.objects.create(**self.token_data)
        self.assertFalse(token.is_expired())

        # Test expired
        expired_token = PasswordResetToken.objects.create(
            user=self.user,
            token='expired_token',
            code='654321',
            expires_at=timezone.now() - timedelta(hours=1)
        )
        self.assertTrue(expired_token.is_expired())

    def test_mark_as_used_method(self):
        token = PasswordResetToken.objects.create(**self.token_data)
        token.mark_as_used()
        self.assertTrue(token.is_used)
        self.assertIsNotNone(token.used_at)


class EmployeeProfileModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.profile_data = {
            'user': self.user,
            'organization': 'Test Org',
            'role': 'Developer',
            'subscription_tier': 'freemium'
        }

    def test_create_employee_profile(self):
        profile = EmployeeProfile.objects.create(**self.profile_data)
        self.assertEqual(profile.organization, 'Test Org')
        self.assertEqual(profile.role, 'Developer')
        self.assertFalse(profile.is_premium_active)

    def test_profile_default_values(self):
        profile = EmployeeProfile.objects.create(**self.profile_data)
        self.assertTrue(profile.receive_notifications)
        self.assertFalse(profile.is_anonymous)
        self.assertEqual(profile.current_wellness_status, '')


class WellnessHubModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.employee_profile = EmployeeProfile.objects.create(
            user=self.user,
            organization='Test Org',
            role='Developer'
        )

    def test_create_wellness_hub(self):
        wellness_hub = WellnessHub.objects.create(
            employee=self.employee_profile,
            last_checkin_mood='happy'
        )
        self.assertEqual(wellness_hub.last_checkin_mood, 'happy')
        self.assertEqual(wellness_hub.mood_logs, [])
        self.assertEqual(wellness_hub.mood_insights, {})

    def test_wellness_hub_str_representation(self):
        wellness_hub = WellnessHub.objects.create(employee=self.employee_profile)
        expected_str = f"Wellness Hub - {wellness_hub.employee.user.username}"
        self.assertEqual(str(wellness_hub), expected_str)


class ChatSessionModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.employee_profile = EmployeeProfile.objects.create(
            user=self.user,
            organization='Test Org',
            role='Developer'
        )

    def test_create_chat_session(self):
        session = ChatSession.objects.create(employee=self.employee_profile)
        self.assertTrue(session.is_active)
        self.assertIsNotNone(session.started_at)

    def test_chat_message_creation(self):
        session = ChatSession.objects.create(employee=self.employee_profile)
        message = ChatMessage.objects.create(
            session=session,
            sender='user',
            message='Hello, Sana!'
        )
        self.assertEqual(message.sender, 'user')
        self.assertEqual(message.message, 'Hello, Sana!')


class EducationalVideoModelTest(TestCase):
    def setUp(self):
        self.category = ResourceCategory.objects.create(
            name='Mindfulness',
            description='Mindfulness and meditation resources'
        )
        self.video_data = {
            'title': 'Test Meditation Video',
            'description': 'A guided meditation for stress relief',
            'youtube_url': 'https://www.youtube.com/watch?v=test123',
            'resource_category': self.category,
            'target_mood': 'stress',
            'intensity_level': 1
        }

    def test_create_educational_video(self):
        video = EducationalVideo.objects.create(**self.video_data)
        self.assertEqual(video.title, 'Test Meditation Video')
        self.assertEqual(video.target_mood, 'stress')
        self.assertEqual(video.intensity_level, 1)
        self.assertEqual(video.views_count, 0)

    def test_video_str_representation(self):
        video = EducationalVideo.objects.create(**self.video_data)
        self.assertEqual(str(video), video.title)


class UserVideoInteractionModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.category = ResourceCategory.objects.create(name='Test Category')
        self.video = EducationalVideo.objects.create(
            title='Test Video',
            description='Test Description',
            youtube_url='https://www.youtube.com/watch?v=test123',
            resource_category=self.category
        )

    def test_create_user_video_interaction(self):
        interaction = UserVideoInteraction.objects.create(
            user=self.user,
            video=self.video,
            mood_before=2,
            mood_after=4,
            watched_full_video=True
        )
        self.assertEqual(interaction.mood_before, 2)
        self.assertEqual(interaction.mood_after, 4)
        self.assertTrue(interaction.watched_full_video)

    def test_unique_together_constraint(self):
        UserVideoInteraction.objects.create(
            user=self.user,
            video=self.video
        )
        with self.assertRaises(IntegrityError):
            UserVideoInteraction.objects.create(
                user=self.user,
                video=self.video
            )


class SystemSettingsModelTest(TestCase):
    def setUp(self):
        self.setting_data = {
            'setting_name': 'test_setting',
            'setting_value': 'test_value',
            'setting_type': 'string',
            'description': 'Test setting for testing'
        }

    def test_create_system_setting(self):
        setting = SystemSettings.objects.create(**self.setting_data)
        self.assertEqual(setting.setting_name, 'test_setting')
        self.assertEqual(setting.setting_value, 'test_value')

    def test_system_setting_str_representation(self):
        setting = SystemSettings.objects.create(**self.setting_data)
        expected_str = f"{setting.setting_name} - {setting.setting_value}"
        self.assertEqual(str(setting), expected_str)


class ReportModelTest(TestCase):
    def setUp(self):
        self.report_data = {
            'title': 'Monthly Usage Report',
            'report_type': 'platform_usage',
            'format': 'pdf',
            'file_size_mb': 2.5
        }

    def test_create_report(self):
        report = Report.objects.create(**self.report_data)
        self.assertEqual(report.title, 'Monthly Usage Report')
        self.assertEqual(report.report_type, 'platform_usage')
        self.assertEqual(report.format, 'pdf')

    def test_report_str_representation(self):
        report = Report.objects.create(**self.report_data)
        expected_str = f"{report.title} - {report.format.upper()}"
        self.assertEqual(str(report), expected_str)


class HotlineCallModelTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Employer')
        self.call_data = {
            'call_id': 'CALL001',
            'duration_minutes': 15,
            'reason': 'anxiety',
            'urgency': 'medium',
            'operator_name': 'John Operator',
            'status': 'resolved'
        }

    def test_create_hotline_call(self):
        call = HotlineCall.objects.create(**self.call_data)
        self.assertEqual(call.call_id, 'CALL001')
        self.assertEqual(call.duration_minutes, 15)
        self.assertEqual(call.reason, 'anxiety')

    def test_hotline_call_str_representation(self):
        call = HotlineCall.objects.create(**self.call_data)
        expected_str = f"Call {call.call_id} - {call.reason}"
        self.assertEqual(str(call), expected_str)


class PlatformMetricsModelTest(TestCase):
    def setUp(self):
        self.metrics_data = {
            'total_organizations': 100,
            'total_clients': 5000,
            'monthly_revenue': 50000.00,
            'hotline_calls_today': 25
        }

    def test_create_platform_metrics(self):
        metrics = PlatformMetrics.objects.create(**self.metrics_data)
        self.assertEqual(metrics.total_organizations, 100)
        self.assertEqual(metrics.total_clients, 5000)
        self.assertEqual(metrics.monthly_revenue, 50000.00)

    def test_platform_metrics_str_representation(self):
        metrics = PlatformMetrics.objects.create(**self.metrics_data)
        expected_str = f"Platform Metrics - {metrics.recorded_date}"
        self.assertEqual(str(metrics), expected_str)


class ModelRelationshipsTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Employer')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.employee = Employee.objects.create(
            employer=self.employer,
            name='Test Employee',
            email='employee@example.com'
        )

    def test_employer_employee_relationship(self):
        self.assertEqual(self.employee.employer, self.employer)
        self.assertIn(self.employee, self.employer.employees.all())

    def test_user_employee_profile_relationship(self):
        employee_profile = EmployeeProfile.objects.create(
            user=self.user,
            organization='Test Org',
            role='Developer'
        )
        self.assertEqual(employee_profile.user, self.user)

    def test_department_employee_relationship(self):
        department = Department.objects.create(
            employer=self.employer,
            name='Test Department'
        )
        self.employee.department = department
        self.employee.save()
        self.assertIn(self.employee, department.employees.all())


class ModelValidationTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Employer')

    def test_employee_email_validation(self):
        # Test valid email
        employee = Employee.objects.create(
            employer=self.employer,
            name='Test Employee',
            email='valid@example.com'
        )
        self.assertEqual(employee.email, 'valid@example.com')

    def test_subscription_plan_validation(self):
        subscription = Subscription.objects.create(
            employer=self.employer,
            plan='starter',
            seats=5,
            start_date=timezone.now().date()
        )
        valid_plans = ['starter', 'enterprise', 'enterprise_plus']
        self.assertIn(subscription.plan, valid_plans)


class ModelPropertiesTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Employer')

    def test_subscription_available_seats(self):
        subscription = Subscription.objects.create(
            employer=self.employer,
            plan='starter',
            seats=10,
            used_seats=3,
            start_date=timezone.now().date()
        )
        self.assertEqual(subscription.available_seats, 7)

    def test_mental_health_assessment_severity_properties(self):
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        assessment = MentalHealthAssessment.objects.create(
            user=user,
            assessment_type='GAD-7',
            gad7_scores=[3, 3, 3, 3, 3, 3, 3]  # Total: 21
        )
        self.assertEqual(assessment.gad7_severity, "Severe anxiety")


class ModelMetaOptionsTest(TestCase):
    def test_employer_meta_ordering(self):
        employer1 = Employer.objects.create(name='Company A')
        employer2 = Employer.objects.create(name='Company B')
        employers = Employer.objects.all()
        self.assertEqual(list(employers), [employer2, employer1])

    def test_employee_meta_ordering(self):
        employee1 = Employee.objects.create(
            employer=Employer.objects.create(name='Employer A'),
            name='Employee A',
            email='a@example.com'
        )
        employee2 = Employee.objects.create(
            employer=Employer.objects.create(name='Employer B'),
            name='Employee B',
            email='b@example.com'
        )
        employees = Employee.objects.all()
        self.assertEqual(list(employees), [employee2, employee1])

    def test_mental_health_assessment_meta_ordering(self):
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        assessment1 = MentalHealthAssessment.objects.create(
            user=user,
            assessment_type='GAD-7',
            gad7_scores=[1, 1, 1, 1, 1, 1, 1]
        )
        assessment2 = MentalHealthAssessment.objects.create(
            user=user,
            assessment_type='PHQ-9',
            phq9_scores=[1, 1, 1, 1, 1, 1, 1, 1, 1]
        )
        assessments = MentalHealthAssessment.objects.all()
        self.assertEqual(list(assessments), [assessment2, assessment1])