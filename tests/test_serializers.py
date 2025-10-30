# tests_serializers.py
import pytest
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from datetime import timedelta
import json

from obeeomaapp.serializers import *
from obeeomaapp.models import *

User = get_user_model()


class SignupSerializerTest(TestCase):
    def setUp(self):
        self.valid_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'SecurePass123!',
            'confirm_password': 'SecurePass123!',
            'role': 'employee'
        }

    def test_valid_signup_data(self):
        serializer = SignupSerializer(data=self.valid_data)
        self.assertTrue(serializer.is_valid())

    def test_password_mismatch(self):
        invalid_data = self.valid_data.copy()
        invalid_data['confirm_password'] = 'DifferentPass123!'
        serializer = SignupSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('confirm_password', serializer.errors)

    def test_weak_password(self):
        weak_data = self.valid_data.copy()
        weak_data['password'] = '123'
        weak_data['confirm_password'] = '123'
        serializer = SignupSerializer(data=weak_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)

    def test_user_creation(self):
        serializer = SignupSerializer(data=self.valid_data)
        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.role, 'employee')
        self.assertTrue(user.check_password('SecurePass123!'))

    def test_default_role(self):
        data = self.valid_data.copy()
        data.pop('role')
        serializer = SignupSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        self.assertEqual(user.role, 'employee')


class LoginSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.valid_data = {
            'username': 'testuser',
            'password': 'testpass123'
        }

    def test_valid_login(self):
        serializer = LoginSerializer(data=self.valid_data, context={'request': None})
        self.assertTrue(serializer.is_valid())
        validated_data = serializer.validate(self.valid_data)
        self.assertIn('user', validated_data)
        self.assertEqual(validated_data['user'], self.user)

    def test_invalid_credentials(self):
        invalid_data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        serializer = LoginSerializer(data=invalid_data, context={'request': None})
        with self.assertRaises(ValidationError):
            serializer.validate(invalid_data)

    def test_missing_fields(self):
        missing_username = {'password': 'testpass123'}
        serializer = LoginSerializer(data=missing_username, context={'request': None})
        with self.assertRaises(ValidationError):
            serializer.validate(missing_username)

        missing_password = {'username': 'testuser'}
        serializer = LoginSerializer(data=missing_password, context={'request': None})
        with self.assertRaises(ValidationError):
            serializer.validate(missing_password)

    def test_inactive_user(self):
        self.user.is_active = False
        self.user.save()
        
        serializer = LoginSerializer(data=self.valid_data, context={'request': None})
        with self.assertRaises(ValidationError):
            serializer.validate(self.valid_data)


class LogoutSerializerTest(TestCase):
    def test_valid_logout(self):
        data = {'refresh': 'valid_refresh_token'}
        serializer = LogoutSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_missing_refresh_token(self):
        serializer = LogoutSerializer(data={})
        self.assertFalse(serializer.is_valid())
        self.assertIn('refresh', serializer.errors)


class PasswordResetSerializerTest(TestCase):
    def test_valid_email(self):
        data = {'email': 'test@example.com'}
        serializer = PasswordResetSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_invalid_email(self):
        data = {'email': 'invalid-email'}
        serializer = PasswordResetSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)


class UserSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            role='employee'
        )

    def test_user_serialization(self):
        serializer = UserSerializer(instance=self.user)
        expected_fields = ['id', 'username', 'email', 'role', 'avatar', 'onboarding_completed']
        self.assertEqual(set(serializer.data.keys()), set(expected_fields))
        self.assertEqual(serializer.data['username'], 'testuser')
        self.assertEqual(serializer.data['email'], 'test@example.com')
        self.assertEqual(serializer.data['role'], 'employee')


class EmployerSerializerTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Company')

    def test_employer_serialization(self):
        serializer = EmployerSerializer(instance=self.employer)
        self.assertEqual(serializer.data['name'], 'Test Company')
        self.assertTrue(serializer.data['is_active'])


class EmployeeSerializerTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Company')
        self.department = Department.objects.create(
            employer=self.employer,
            name='Engineering'
        )
        self.employee = Employee.objects.create(
            employer=self.employer,
            department=self.department,
            name='John Doe',
            email='john@example.com',
            status='active'
        )

    def test_employee_serialization(self):
        serializer = EmployeeSerializer(instance=self.employee)
        self.assertEqual(serializer.data['name'], 'John Doe')
        self.assertEqual(serializer.data['email'], 'john@example.com')
        self.assertEqual(serializer.data['status'], 'active')
        self.assertEqual(serializer.data['employer_name'], 'Test Company')
        self.assertEqual(serializer.data['department_name'], 'Engineering')


class MentalHealthAssessmentSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.valid_gad7_data = {
            'user': self.user.id,
            'assessment_type': 'GAD-7',
            'gad7_scores': [1, 2, 1, 1, 0, 1, 2]
        }

    def test_valid_gad7_assessment(self):
        serializer = MentalHealthAssessmentSerializer(data=self.valid_gad7_data)
        self.assertTrue(serializer.is_valid())

    def test_invalid_gad7_scores_count(self):
        invalid_data = self.valid_gad7_data.copy()
        invalid_data['gad7_scores'] = [1, 2, 1]  # Only 3 scores instead of 7
        serializer = MentalHealthAssessmentSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    def test_invalid_gad7_score_range(self):
        invalid_data = self.valid_gad7_data.copy()
        invalid_data['gad7_scores'] = [1, 2, 5, 1, 0, 1, 2]  # 5 is out of range
        serializer = MentalHealthAssessmentSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    def test_phq9_assessment(self):
        phq9_data = {
            'user': self.user.id,
            'assessment_type': 'PHQ-9',
            'phq9_scores': [1, 1, 1, 1, 1, 1, 1, 1, 1]
        }
        serializer = MentalHealthAssessmentSerializer(data=phq9_data)
        self.assertTrue(serializer.is_valid())

    def test_both_assessments(self):
        both_data = {
            'user': self.user.id,
            'assessment_type': 'BOTH',
            'gad7_scores': [1, 2, 1, 1, 0, 1, 2],
            'phq9_scores': [1, 1, 1, 1, 1, 1, 1, 1, 1]
        }
        serializer = MentalHealthAssessmentSerializer(data=both_data)
        self.assertTrue(serializer.is_valid())


class AssessmentResponseSerializerTest(TestCase):
    def test_valid_gad7_response(self):
        data = {
            'assessment_type': 'GAD-7',
            'gad7_responses': [0, 1, 2, 1, 0, 1, 2]
        }
        serializer = AssessmentResponseSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_invalid_gad7_response_count(self):
        data = {
            'assessment_type': 'GAD-7',
            'gad7_responses': [0, 1, 2]  # Wrong count
        }
        serializer = AssessmentResponseSerializer(data=data)
        self.assertFalse(serializer.is_valid())

    def test_valid_phq9_response(self):
        data = {
            'assessment_type': 'PHQ-9',
            'phq9_responses': [0, 1, 2, 1, 0, 1, 2, 1, 0]
        }
        serializer = AssessmentResponseSerializer(data=data)
        self.assertTrue(serializer.is_valid())


class EmployeeInvitationCreateSerializerTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Company')
        self.user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='testpass123',
            role='employer'
        )
        self.valid_data = {
            'email': 'newemployee@example.com',
            'message': 'Welcome to our team!',
            'expires_at': timezone.now() + timedelta(days=7)
        }

    def test_invitation_creation(self):
        context = {'employer': self.employer, 'user': self.user}
        serializer = EmployeeInvitationCreateSerializer(
            data=self.valid_data, 
            context=context
        )
        self.assertTrue(serializer.is_valid())
        invitation = serializer.save()
        self.assertEqual(invitation.email, 'newemployee@example.com')
        self.assertEqual(invitation.employer, self.employer)
        self.assertEqual(invitation.invited_by, self.user)
        self.assertIsNotNone(invitation.token)


class EmployeeInvitationAcceptSerializerTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Company')
        self.user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='testpass123'
        )
        self.invitation = EmployeeInvitation.objects.create(
            employer=self.employer,
            invited_by=self.user,
            email='new@example.com',
            token='test-token-123',
            expires_at=timezone.now() + timedelta(days=1)
        )

    def test_valid_invitation_acceptance(self):
        data = {
            'token': 'test-token-123',
            'username': 'newuser',
            'password': 'newpass123'
        }
        serializer = EmployeeInvitationAcceptSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        self.assertEqual(user.username, 'newuser')
        self.assertEqual(user.email, 'new@example.com')
        self.assertEqual(user.role, 'employee')

        # Check that invitation was marked as accepted
        self.invitation.refresh_from_db()
        self.assertTrue(self.invitation.accepted)
        self.assertIsNotNone(self.invitation.accepted_at)

        # Check that employee was created
        employee = Employee.objects.get(email='new@example.com')
        self.assertEqual(employee.employer, self.employer)

    def test_expired_invitation(self):
        self.invitation.expires_at = timezone.now() - timedelta(days=1)
        self.invitation.save()

        data = {
            'token': 'test-token-123',
            'username': 'newuser',
            'password': 'newpass123'
        }
        serializer = EmployeeInvitationAcceptSerializer(data=data)
        with self.assertRaises(ValidationError):
            serializer.validate(data)

    def test_invalid_token(self):
        data = {
            'token': 'invalid-token',
            'username': 'newuser',
            'password': 'newpass123'
        }
        serializer = EmployeeInvitationAcceptSerializer(data=data)
        with self.assertRaises(ValidationError):
            serializer.validate(data)


class SubscriptionSerializerTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Company')
        self.subscription = Subscription.objects.create(
            employer=self.employer,
            plan='starter',
            amount=99.00,
            seats=10,
            start_date=timezone.now().date(),
            is_active=True
        )

    def test_subscription_serialization(self):
        serializer = SubscriptionSerializer(instance=self.subscription)
        self.assertEqual(serializer.data['plan'], 'starter')
        self.assertEqual(serializer.data['amount'], '99.00')
        self.assertEqual(serializer.data['seats'], 10)
        self.assertTrue(serializer.data['is_active'])


class EducationalVideoSerializerTest(TestCase):
    def setUp(self):
        self.category = ResourceCategory.objects.create(
            name='Mindfulness',
            description='Mindfulness resources'
        )
        self.video = EducationalVideo.objects.create(
            title='Test Video',
            description='Test Description',
            youtube_url='https://www.youtube.com/watch?v=test123',
            resource_category=self.category,
            target_mood='anxiety',
            intensity_level=1
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_video_serialization(self):
        serializer = EducationalVideoSerializer(instance=self.video)
        self.assertEqual(serializer.data['title'], 'Test Video')
        self.assertEqual(serializer.data['resource_category_name'], 'Mindfulness')
        self.assertEqual(serializer.data['target_mood'], 'anxiety')

    def test_youtube_embed_url_conversion(self):
        serializer = EducationalVideoSerializer(instance=self.video)
        self.assertIn('embed', serializer.data['youtube_embed_url'])

    def test_invalid_youtube_url(self):
        invalid_data = {
            'title': 'Test Video',
            'description': 'Test Description',
            'youtube_url': 'https://invalid.com/watch?v=test123',
            'resource_category': self.category.id,
            'target_mood': 'anxiety',
            'intensity_level': 1
        }
        serializer = EducationalVideoSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('youtube_url', serializer.errors)


class UserVideoInteractionSerializerTest(TestCase):
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
        self.interaction = UserVideoInteraction.objects.create(
            user=self.user,
            video=self.video,
            mood_before=2,
            mood_after=4,
            watched_full_video=True
        )

    def test_interaction_serialization(self):
        serializer = UserVideoInteractionSerializer(instance=self.interaction)
        self.assertEqual(serializer.data['mood_before'], 2)
        self.assertEqual(serializer.data['mood_after'], 4)
        self.assertTrue(serializer.data['watched_full_video'])
        self.assertEqual(serializer.data['video_title'], 'Test Video')

    def test_mood_validation(self):
        # Test that mood validation works (even if mood decreases)
        data = {
            'video': self.video.id,
            'mood_before': 4,
            'mood_after': 1  # Mood decreased significantly
        }
        serializer = UserVideoInteractionSerializer(data=data)
        self.assertTrue(serializer.is_valid())  # Should still be valid


class DepartmentSerializerTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Company')
        self.department = Department.objects.create(
            employer=self.employer,
            name='Engineering'
        )
        # Create some employees
        self.employee1 = Employee.objects.create(
            employer=self.employer,
            department=self.department,
            name='Employee 1',
            email='emp1@example.com'
        )
        self.employee2 = Employee.objects.create(
            employer=self.employer,
            department=self.department,
            name='Employee 2',
            email='emp2@example.com'
        )

    def test_department_serialization(self):
        serializer = DepartmentSerializer(instance=self.department)
        self.assertEqual(serializer.data['name'], 'Engineering')
        self.assertEqual(serializer.data['employee_count'], 2)
        self.assertFalse(serializer.data['at_risk'])


class ResourceCategorySerializerTest(TestCase):
    def setUp(self):
        self.category = ResourceCategory.objects.create(
            name='Mindfulness',
            description='Mindfulness resources',
            icon='',
        )
        # Create some videos for this category
        EducationalVideo.objects.create(
            title='Video 1',
            description='Description 1',
            youtube_url='https://www.youtube.com/watch?v=test1',
            resource_category=self.category,
            is_active=True
        )
        EducationalVideo.objects.create(
            title='Video 2',
            description='Description 2',
            youtube_url='https://www.youtube.com/watch?v=test2',
            resource_category=self.category,
            is_active=True
        )

    def test_resource_category_serialization(self):
        serializer = ResourceCategorySerializer(instance=self.category)
        self.assertEqual(serializer.data['name'], 'Mindfulness')
        self.assertEqual(serializer.data['total_videos'], 2)
        self.assertEqual(serializer.data['icon'], '🧠')
        self.assertEqual(serializer.data['color_code'], '#667eea')


class MoodCheckInSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.mood_checkin = MoodCheckIn.objects.create(
            user=self.user,
            mood='happy',
            note='Feeling great today!'
        )

    def test_mood_checkin_serialization(self):
        serializer = MoodCheckInSerializer(instance=self.mood_checkin)
        self.assertEqual(serializer.data['mood'], 'happy')
        self.assertEqual(serializer.data['note'], 'Feeling great today!')
        self.assertIn('checked_in_at', serializer.data)


class SelfAssessmentSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.assessment = SelfAssessment.objects.create(
            user=self.user,
            assessment_type='GAD-7',
            score=8
        )

    def test_self_assessment_serialization(self):
        serializer = SelfAssessmentSerializer(instance=self.assessment)
        self.assertEqual(serializer.data['assessment_type'], 'GAD-7')
        self.assertEqual(serializer.data['score'], 8)
        self.assertIn('submitted_at', serializer.data)


class ChatSessionSerializerTest(TestCase):
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
        self.chat_session = ChatSession.objects.create(
            employee=self.employee_profile
        )

    def test_chat_session_serialization(self):
        serializer = ChatSessionSerializer(instance=self.chat_session)
        self.assertTrue(serializer.data['is_active'])
        self.assertIn('started_at', serializer.data)


class ProgressSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.progress = Progress.objects.create(
            user=self.user,
            date=timezone.now().date(),
            mood_score=8,
            notes='Good day today'
        )

    def test_progress_serialization(self):
        serializer = ProgressSerializer(instance=self.progress)
        self.assertEqual(serializer.data['mood_score'], 8)
        self.assertEqual(serializer.data['notes'], 'Good day today')
        self.assertIn('date', serializer.data)


class PlatformMetricsSerializerTest(TestCase):
    def setUp(self):
        self.metrics = PlatformMetrics.objects.create(
            total_organizations=100,
            total_clients=5000,
            monthly_revenue=50000.00,
            hotline_calls_today=25
        )

    def test_platform_metrics_serialization(self):
        serializer = PlatformMetricsSerializer(instance=self.metrics)
        self.assertEqual(serializer.data['total_organizations'], 100)
        self.assertEqual(serializer.data['total_clients'], 5000)
        self.assertEqual(serializer.data['monthly_revenue'], '50000.00')
        self.assertEqual(serializer.data['hotline_calls_today'], 25)


class HotlineCallSerializerTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Company')
        self.hotline_call = HotlineCall.objects.create(
            call_id='CALL001',
            duration_minutes=15,
            reason='anxiety',
            urgency='medium',
            operator_name='John Operator',
            status='resolved',
            organization=self.employer
        )

    def test_hotline_call_serialization(self):
        serializer = HotlineCallSerializer(instance=self.hotline_call)
        self.assertEqual(serializer.data['call_id'], 'CALL001')
        self.assertEqual(serializer.data['duration_minutes'], 15)
        self.assertEqual(serializer.data['reason'], 'anxiety')
        self.assertEqual(serializer.data['organization_name'], 'Test Company')
        self.assertEqual(serializer.data['duration_display'], '00:15')


class SystemAdminOverviewSerializerTest(TestCase):
    def test_system_admin_overview_serializer(self):
        data = {
            'total_organizations': 150,
            'total_clients': 7500,
            'monthly_revenue': 75000.00,
            'hotline_calls_today': 35,
            'organizations_this_month': 10,
            'clients_this_month': 500,
            'revenue_growth_percentage': 15.50,
            'hotline_growth_percentage': 8.75
        }
        serializer = SystemAdminOverviewSerializer(data=data)
        self.assertTrue(serializer.is_valid())


class EmployeeProfileSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.employee_profile = EmployeeProfile.objects.create(
            user=self.user,
            organization='Test Company',
            role='Developer',
            subscription_tier='premium',
            is_premium_active=True
        )

    def test_employee_profile_serialization(self):
        serializer = EmployeeProfileSerializer(instance=self.employee_profile)
        self.assertEqual(serializer.data['organization'], 'Test Company')
        self.assertEqual(serializer.data['role'], 'Developer')
        self.assertEqual(serializer.data['subscription_tier'], 'premium')
        self.assertTrue(serializer.data['is_premium_active'])


class WellnessHubSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.employee_profile = EmployeeProfile.objects.create(
            user=self.user,
            organization='Test Company',
            role='Developer'
        )
        self.wellness_hub = WellnessHub.objects.create(
            employee=self.employee_profile,
            last_checkin_mood='happy',
            mood_logs=['happy', 'calm', 'energetic'],
            mood_insights={'trend': 'improving', 'average_mood': 4.2}
        )

    def test_wellness_hub_serialization(self):
        serializer = WellnessHubSerializer(instance=self.wellness_hub)
        self.assertEqual(serializer.data['last_checkin_mood'], 'happy')
        self.assertEqual(serializer.data['mood_logs'], ['happy', 'calm', 'energetic'])
        self.assertEqual(serializer.data['mood_insights'], {'trend': 'improving', 'average_mood': 4.2})


class SubscriptionManagementSerializerTest(TestCase):
    def setUp(self):
        self.employer = Employer.objects.create(name='Test Company')
        self.subscription_plan = SubscriptionPlan.objects.create(
            name='starter',
            display_name='Starter Plan',
            price=99.00,
            seats=10,
            description='Basic plan',
            features=['Feature 1', 'Feature 2']
        )
        self.subscription = Subscription.objects.create(
            employer=self.employer,
            plan='starter',
            seats=10,
            used_seats=3,
            start_date=timezone.now().date(),
            is_active=True
        )

    def test_subscription_management_serialization(self):
        serializer = SubscriptionManagementSerializer(instance=self.subscription)
        self.assertEqual(serializer.data['plan'], 'starter')
        self.assertEqual(serializer.data['seats'], 10)
        self.assertEqual(serializer.data['used_seats'], 3)
        self.assertEqual(serializer.data['available_seats'], 7)
        self.assertTrue(serializer.data['is_active'])


class SerializerEdgeCasesTest(TestCase):
    def test_empty_data_validation(self):
        """Test serializers with empty data"""
        serializers_to_test = [
            (SignupSerializer, {}),
            (LoginSerializer, {}),
            (PasswordResetSerializer, {}),
        ]
        
        for serializer_class, empty_data in serializers_to_test:
            serializer = serializer_class(data=empty_data)
            self.assertFalse(serializer.is_valid())

    def test_serializer_with_none_instance(self):
        """Test serializers with None instance"""
        serializer = UserSerializer(instance=None)
        self.assertEqual(serializer.data, {})

    def test_partial_updates(self):
        """Test serializers with partial data"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Test partial update
        serializer = UserSerializer(
            instance=user, 
            data={'username': 'updateduser'}, 
            partial=True
        )
        self.assertTrue(serializer.is_valid())

    def test_read_only_fields(self):
        """Test that read-only fields are respected"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Try to update read-only field
        serializer = UserSerializer(
            instance=user,
            data={'id': 999, 'username': 'newusername'},  # id should be read-only
            partial=True
        )
        if serializer.is_valid():
            updated_user = serializer.save()
            # ID should not change even if provided in data
            self.assertEqual(updated_user.id, user.id)


# Run the tests with: python manage.py test your_app.tests_serializers