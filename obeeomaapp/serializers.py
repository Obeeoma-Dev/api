# serializers.py
from rest_framework.exceptions import AuthenticationFailed

from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.password_validation import validate_password
from obeeomaapp.models import *
from .models import (ResourceCategory, EducationalVideo, UserVideoInteraction,)
User = get_user_model()

# signup serializer
class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, default="employee")

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'confirm_password', 'role')

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords don’t match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        role = validated_data.pop('role', 'employee')

        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            role=role
        )
        user.set_password(validated_data['password'])
        user.save()

        return user



# Login Serializer
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            # Authenticate the user
            user = authenticate(
                request=self.context.get('request'),
                username=username,
                password=password
            )
            
            if not user:
                raise serializers.ValidationError('Invalid credentials. Please try again.')
                
            if not user.is_active:
                raise serializers.ValidationError('Account is disabled.')
                
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError('Both username and password are required.')

    def create(self, validated_data):
        return validated_data
    
    
# Logout Serializer
class LogoutSerializer(serializers.Serializer):
     refresh = serializers.CharField()

     def validate_refresh(self, value):
        if not value:
            raise serializers.ValidationError("Refresh token is required.")
        return value


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def create(self, validated_data):
        return validated_data

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])

    def create(self, validated_data):
        return validated_data


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'avatar', 'onboarding_completed']



class EmployerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employer
        fields = '__all__'


class EmployeeSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source='department.name', read_only=True)
    employer_name = serializers.CharField(source='employer.name', read_only=True)
    
    class Meta:
        model = Employee
        fields = ['id', 'employer', 'employer_name', 'department', 'department_name', 'name', 'email', 'status', 'joined_date', 'last_active', 'avatar']


class AIManagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIManagement
        fields = ['id', 'employer', 'title', 'description', 'effectiveness', 'created_at']


class HotlineActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = HotlineActivity
        fields = ['id', 'employer', 'call_count', 'spike_percentage', 'recorded_at']


class EmployeeEngagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployeeEngagement
        fields = ['id', 'employer', 'engagement_rate', 'month', 'notes']

# subcription serializer
class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = ['id', 'employer', 'plan', 'amount', 'start_date', 'end_date', 'is_active']


class RecentActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = RecentActivity
        fields = ['id', 'employer', 'activity_type', 'details', 'timestamp', 'is_important']


class SelfAssessmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = SelfAssessment
        fields = ['id', 'user', 'assessment_type', 'score', 'submitted_at']


class MoodCheckInSerializer(serializers.ModelSerializer):
    class Meta:
        model = MoodCheckIn
        fields = ['id', 'user', 'mood', 'note', 'checked_in_at']


class SelfHelpResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = SelfHelpResource
        fields = ['id', 'title', 'resource_type', 'content', 'created_at']


class ChatbotInteractionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatbotInteraction
        fields = ['id', 'user', 'message', 'response', 'timestamp', 'escalated']



class UserBadgeSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserBadge
        fields = ['id', 'user', 'badge_name', 'awarded_on']


class EngagementStreakSerializer(serializers.ModelSerializer):
    class Meta:
        model = EngagementStreak
        fields = ['id', 'user', 'streak_count', 'last_active_date']


class EmployeeInvitationCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployeeInvitation
        fields = ['id', 'email', 'message', 'expires_at']

    def create(self, validated_data):
        from secrets import token_urlsafe
        employer = self.context['employer']
        inviter = self.context['user']
        token = token_urlsafe(32)
        return EmployeeInvitation.objects.create(
            employer=employer,
            invited_by=inviter,
            token=token,
            **validated_data
        )


class EmployeeInvitationAcceptSerializer(serializers.Serializer):
    token = serializers.CharField()
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        token = attrs['token']
        try:
            invitation = EmployeeInvitation.objects.get(token=token, accepted=False)
        except EmployeeInvitation.DoesNotExist:
            raise serializers.ValidationError('Invalid or used invitation token.')
        from django.utils import timezone
        if invitation.expires_at < timezone.now():
            raise serializers.ValidationError('Invitation has expired.')
        attrs['invitation'] = invitation
        return attrs

    def create(self, validated_data):
        invitation = validated_data['invitation']
        username = validated_data['username']
        password = validated_data['password']

        # Create user
        user = User.objects.create_user(
            username=username,
            email=invitation.email,
            role='employee',
            password=password
        )
        # Link to employer in Employee model
        Employee.objects.create(
            employer=invitation.employer,
            name=username,
            email=invitation.email
        )
        from django.utils import timezone
        invitation.accepted = True
        invitation.accepted_at = timezone.now()
        invitation.save(update_fields=['accepted', 'accepted_at'])
        return user


# --- Employee Profile ---
class EmployeeProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployeeProfile
        fields = '__all__'
        read_only_fields = ['user', 'joined_on']

# --- Avatar ---
class AvatarProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = AvatarProfile
        fields = '__all__'
        read_only_fields = ['employee']

# --- Wellness Hub ---
class WellnessHubSerializer(serializers.ModelSerializer):
    class Meta:
        model = WellnessHub
        fields = '__all__'
        read_only_fields = ['employee', 'updated_at']


# --- Assessment Results ---
class AssessmentResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssessmentResult
        fields = '__all__'
        read_only_fields = ['employee', 'submitted_on']

# --- Educational Resources ---
class EducationalResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = EducationalResource
        fields = '__all__'

# --- Crisis Trigger ---
class CrisisTriggerSerializer(serializers.ModelSerializer):
    class Meta:
        model = CrisisTrigger
        fields = '__all__'
        read_only_fields = ['employee', 'triggered_on']

# --- Notifications ---
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = '__all__'
        read_only_fields = ['employee', 'sent_on']

# --- Engagement Tracker ---
class EngagementTrackerSerializer(serializers.ModelSerializer):
    class Meta:
        model = EngagementTracker
        fields = '__all__'
        read_only_fields = ['employee']

# --- Feedback ---
class FeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feedback
        fields = '__all__'
        read_only_fields = ['employee', 'submitted_on']

# --- Sana Chat Sessions ---
class ChatSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatSession
        fields = '__all__'
        read_only_fields = ['employee', 'started_at']

class ChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = '__all__'
        read_only_fields = ['session', 'timestamp']

# --- Recommendations ---
class RecommendationLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecommendationLog
        fields = '__all__'
        read_only_fields = ['employee', 'recommended_on']



# Assessment Response Serializers
class AssessmentResponseSerializer(serializers.Serializer):
    """Serializer for handling assessment responses"""
    assessment_type = serializers.ChoiceField(choices=['GAD-7', 'PHQ-9', 'BOTH'])
    gad7_responses = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=3),
        required=False,
        allow_empty=True
    )
    phq9_responses = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=3),
        required=False,
        allow_empty=True
    )

    def validate(self, data):
        assessment_type = data.get('assessment_type')
        gad7_responses = data.get('gad7_responses', [])
        phq9_responses = data.get('phq9_responses', [])

        if assessment_type == 'GAD-7':
            if not gad7_responses:
                raise serializers.ValidationError('GAD-7 responses are required for GAD-7 assessment.')
            if len(gad7_responses) != 7:
                raise serializers.ValidationError('GAD-7 must have exactly 7 responses.')
                
        elif assessment_type == 'PHQ-9':
            if not phq9_responses:
                raise serializers.ValidationError('PHQ-9 responses are required for PHQ-9 assessment.')
            if len(phq9_responses) != 9:
                raise serializers.ValidationError('PHQ-9 must have exactly 9 responses.')
                
        elif assessment_type == 'BOTH':
            if not gad7_responses or not phq9_responses:
                raise serializers.ValidationError('Both GAD-7 and PHQ-9 responses are required.')
            if len(gad7_responses) != 7:
                raise serializers.ValidationError('GAD-7 must have exactly 7 responses.')
            if len(phq9_responses) != 9:
                raise serializers.ValidationError('PHQ-9 must have exactly 9 responses.')

        return data

class MentalHealthAssessmentSerializer(serializers.ModelSerializer):
    gad7_severity = serializers.CharField(read_only=True)
    phq9_severity = serializers.CharField(read_only=True)
    
    class Meta:
        model = MentalHealthAssessment
        fields = [
            'id', 'user', 'assessment_type', 'gad7_scores', 'phq9_scores', 
            'gad7_total', 'phq9_total', 'gad7_severity', 'phq9_severity', 'assessment_date'
        ]
        read_only_fields = ['user', 'gad7_total', 'phq9_total', 'gad7_severity', 'phq9_severity', 'assessment_date']

    def validate(self, data):
        assessment_type = data.get('assessment_type')
        gad7_scores = data.get('gad7_scores', [])
        phq9_scores = data.get('phq9_scores', [])

        if assessment_type == 'GAD-7':
            if not gad7_scores:
                raise serializers.ValidationError('GAD-7 scores are required for GAD-7 assessment.')
            if len(gad7_scores) != 7:
                raise serializers.ValidationError('GAD-7 must have exactly 7 scores.')
            # Validate each score is between 0-3
            for score in gad7_scores:
                if not isinstance(score, int) or score < 0 or score > 3:
                    raise serializers.ValidationError('Each GAD-7 score must be between 0 and 3.')
                
        elif assessment_type == 'PHQ-9':
            if not phq9_scores:
                raise serializers.ValidationError('PHQ-9 scores are required for PHQ-9 assessment.')
            if len(phq9_scores) != 9:
                raise serializers.ValidationError('PHQ-9 must have exactly 9 scores.')
            # Validate each score is between 0-3
            for score in phq9_scores:
                if not isinstance(score, int) or score < 0 or score > 3:
                    raise serializers.ValidationError('Each PHQ-9 score must be between 0 and 3.')
                    
        elif assessment_type == 'BOTH':
            if not gad7_scores or not phq9_scores:
                raise serializers.ValidationError('Both GAD-7 and PHQ-9 scores are required.')
            if len(gad7_scores) != 7:
                raise serializers.ValidationError('GAD-7 must have exactly 7 scores.')
            if len(phq9_scores) != 9:
                raise serializers.ValidationError('PHQ-9 must have exactly 9 scores.')
            # Validate each score is between 0-3
            for score in gad7_scores + phq9_scores:
                if not isinstance(score, int) or score < 0 or score > 3:
                    raise serializers.ValidationError('Each score must be between 0 and 3.')

        return data

class MentalHealthAssessmentListSerializer(serializers.ModelSerializer):
    """Simplified serializer for listing assessments"""
    class Meta:
        model = MentalHealthAssessment
        fields = [
            'id', 'assessment_type', 'gad7_total', 'phq9_total', 
            'gad7_severity', 'phq9_severity', 'assessment_date'
        ]

class ResourceCategorySerializer(serializers.ModelSerializer):
    total_videos = serializers.SerializerMethodField()
    total_audios = serializers.SerializerMethodField()
    total_articles = serializers.SerializerMethodField()
    total_meditations = serializers.SerializerMethodField()
    
    class Meta:
        model = ResourceCategory
        fields = ['id', 'name', 'description', 'icon', 'color_code', 'total_videos', 
                  'total_audios', 'total_articles', 'total_meditations', 'created_at']
    
    def get_total_videos(self, obj):
        return obj.educational_videos.filter(is_active=True).count()
    
    def get_total_audios(self, obj):
        return obj.calming_audios.filter(is_active=True).count()
    
    def get_total_articles(self, obj):
        return obj.articles.filter(is_published=True).count()
    
    def get_total_meditations(self, obj):
        return obj.guided_meditations.filter(is_active=True).count()


# New Serializers for Dashboard Functionality

class DepartmentSerializer(serializers.ModelSerializer):
    employee_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Department
        fields = ['id', 'name', 'at_risk', 'created_at', 'employee_count']
    
    def get_employee_count(self, obj):
        return obj.employees.count()


class OrganizationSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrganizationSettings
        fields = '__all__'
        read_only_fields = ['employer', 'updated_at']


class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = '__all__'


class BillingHistorySerializer(serializers.ModelSerializer):
    employer_name = serializers.CharField(source='employer.name', read_only=True)
    
    class Meta:
        model = BillingHistory
        fields = ['id', 'employer', 'employer_name', 'invoice_number', 'amount', 'plan_name', 'billing_date', 'status', 'created_at']

# --- Payment Method Serializer ---
class PaymentMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentMethod
        fields = '__all__'
        read_only_fields = ['employer', 'created_at']


class WellnessTestSerializer(serializers.ModelSerializer):
    employee_name = serializers.CharField(source='employee.name', read_only=True)
    department_name = serializers.CharField(source='department.name', read_only=True)
    
    class Meta:
        model = WellnessTest
        fields = ['id', 'employee', 'employee_name', 'department', 'department_name', 'test_type', 'score', 'completed_at']


class ResourceEngagementSerializer(serializers.ModelSerializer):
    employee_name = serializers.CharField(source='employee.name', read_only=True)
    
    class Meta:
        model = ResourceEngagement
        fields = ['id', 'employee', 'employee_name', 'resource_type', 'resource_id', 'completed', 'engagement_date']


class CommonIssueSerializer(serializers.ModelSerializer):
    affected_departments_names = serializers.SerializerMethodField()
    
    class Meta:
        model = CommonIssue
        fields = ['id', 'issue_name', 'description', 'affected_departments', 'affected_departments_names', 'severity', 'identified_at', 'resolved']
    
    def get_affected_departments_names(self, obj):
        return [dept.name for dept in obj.affected_departments.all()]


class ChatEngagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatEngagement
        fields = ['id', 'test_type', 'engagement_count', 'recorded_date']


class DepartmentContributionSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source='department.name', read_only=True)
    
    class Meta:
        model = DepartmentContribution
        fields = ['id', 'department', 'department_name', 'contribution_percentage', 'recorded_date']


class OrganizationActivitySerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source='department.name', read_only=True)
    employee_name = serializers.CharField(source='employee.name', read_only=True)
    
    class Meta:
        model = OrganizationActivity
        fields = ['id', 'activity_type', 'description', 'department', 'department_name', 'employee', 'employee_name', 'created_at']


class ProgressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Progress
        fields = '__all__'
# Dashboard Overview Serializers
class OrganizationOverviewSerializer(serializers.Serializer):
    total_employees = serializers.IntegerField()
    total_tests = serializers.IntegerField()
    average_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    at_risk_departments = serializers.IntegerField()
    recent_activities = OrganizationActivitySerializer(many=True)


class EmployeeManagementSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source='department.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = Employee
        fields = ['id', 'name', 'email', 'department', 'department_name', 'status', 'status_display', 'joined_date', 'avatar']

# subscription Management Serializer
class SubscriptionManagementSerializer(serializers.ModelSerializer):
    plan_details = SubscriptionPlanSerializer(read_only=True)
    payment_method = PaymentMethodSerializer(read_only=True)
    available_seats = serializers.ReadOnlyField()
    
    class Meta:
        model = Subscription
        fields = ['id', 'plan', 'plan_details', 'amount', 'seats', 'used_seats', 'available_seats', 'start_date', 'renewal_date', 'is_active', 'payment_method']


class WellnessReportsSerializer(serializers.Serializer):
    common_issues = serializers.IntegerField()
    resource_engagement = serializers.IntegerField()
    average_wellbeing_trend = serializers.DecimalField(max_digits=5, decimal_places=2)
    at_risk = serializers.IntegerField()
    chat_engagement = ChatEngagementSerializer(many=True)
    department_contributions = DepartmentContributionSerializer(many=True)
    recent_activities = OrganizationActivitySerializer(many=True)


# System Admin Serializers

class PlatformMetricsSerializer(serializers.ModelSerializer):
    class Meta:
        model = PlatformMetrics
        fields = '__all__'


class PlatformUsageSerializer(serializers.ModelSerializer):
    class Meta:
        model = PlatformUsage
        fields = '__all__'

# subscription Revenue Serializer
class SubscriptionRevenueSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionRevenue
        fields = '__all__'


class SystemActivitySerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    
    class Meta:
        model = SystemActivity
        fields = ['id', 'activity_type', 'details', 'organization', 'organization_name', 'created_at']


class HotlineCallSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    duration_display = serializers.SerializerMethodField()
    
    class Meta:
        model = HotlineCall
        fields = ['id', 'call_id', 'duration_minutes', 'duration_display', 'reason', 'urgency', 'operator_name', 'status', 'organization', 'organization_name', 'call_date', 'notes']
    
    def get_duration_display(self, obj):
        hours = obj.duration_minutes // 60
        minutes = obj.duration_minutes % 60
        return f"{hours:02d}:{minutes:02d}"


class AIResourceSerializer(serializers.ModelSerializer):
    effectiveness_display = serializers.SerializerMethodField()
    
    class Meta:
        model = AIResource
        fields = ['id', 'title', 'resource_type', 'recommended_count', 'engagement_rate', 'effectiveness_score', 'effectiveness_display', 'last_updated', 'is_active']
    
    def get_effectiveness_display(self, obj):
        if obj.effectiveness_score >= 80:
            return "High"
        elif obj.effectiveness_score >= 60:
            return "Medium"
        else:
            return "Low"


class ClientEngagementSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    engagement_display = serializers.CharField(source='get_engagement_level_display', read_only=True)
    
    class Meta:
        model = ClientEngagement
        fields = ['id', 'client_name', 'organization', 'organization_name', 'sessions_completed', 'current_streak', 'total_points', 'engagement_level', 'engagement_display', 'last_active', 'avatar_icon']


class RewardProgramSerializer(serializers.ModelSerializer):
    class Meta:
        model = RewardProgram
        fields = '__all__'


"""class FeatureFlagSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeatureFlag
        fields = '__all__'  """


class SystemSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemSettings
        fields = '__all__'


class ReportSerializer(serializers.ModelSerializer):
    format_display = serializers.CharField(source='get_format_display', read_only=True)
    report_type_display = serializers.CharField(source='get_report_type_display', read_only=True)
    
    class Meta:
        model = Report
        fields = ['id', 'title', 'report_type', 'report_type_display', 'format', 'format_display', 'file_size_mb', 'generated_date', 'file_path', 'is_active']


# System Admin Dashboard Serializers

class SystemAdminOverviewSerializer(serializers.Serializer):
    total_organizations = serializers.IntegerField()
    total_clients = serializers.IntegerField()
    monthly_revenue = serializers.DecimalField(max_digits=12, decimal_places=2)
    hotline_calls_today = serializers.IntegerField()
    organizations_this_month = serializers.IntegerField()
    clients_this_month = serializers.IntegerField()
    revenue_growth_percentage = serializers.DecimalField(max_digits=5, decimal_places=2)
    hotline_growth_percentage = serializers.DecimalField(max_digits=5, decimal_places=2)
    platform_usage = PlatformUsageSerializer(many=True)
    subscription_revenue = SubscriptionRevenueSerializer(many=True)
    recent_activities = SystemActivitySerializer(many=True)


class OrganizationsManagementSerializer(serializers.ModelSerializer):
    client_count = serializers.SerializerMethodField()
    current_plan = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_is_active_display', read_only=True)
    
    class Meta:
        model = Employer
        fields = ['id', 'name', 'client_count', 'current_plan', 'is_active', 'status_display', 'joined_date']
    
    def get_client_count(self, obj):
        return obj.employees.count()
    
    def get_current_plan(self, obj):
        # Get the active subscription plan for this employer
        active_subscription = obj.subscriptions.filter(is_active=True).first()
        if active_subscription:
            return active_subscription.plan
        return "No active plan"


class HotlineActivityDashboardSerializer(serializers.Serializer):
    today_calls = serializers.IntegerField()
    average_duration = serializers.CharField()
    active_operators = serializers.IntegerField()
    hourly_volume = serializers.ListField()
    call_reasons = serializers.ListField()
    recent_calls = HotlineCallSerializer(many=True)
    critical_cases = HotlineCallSerializer(many=True)
    operator_performance = serializers.ListField()


class AIManagementDashboardSerializer(serializers.Serializer):
    total_recommendations = serializers.IntegerField()
    average_engagement_rate = serializers.DecimalField(max_digits=5, decimal_places=2)
    ai_accuracy_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    effectiveness_by_type = serializers.ListField()
    weekly_recommendations = serializers.ListField()
    resources = AIResourceSerializer(many=True)
    top_anxiety_triggers = serializers.ListField()


class ClientEngagementDashboardSerializer(serializers.Serializer):
    average_daily_engagement = serializers.DecimalField(max_digits=5, decimal_places=2)
    active_reward_programs = serializers.IntegerField()
    total_points_awarded = serializers.IntegerField()
    weekly_engagement = serializers.ListField()
    reward_redemptions = serializers.ListField()
    clients = ClientEngagementSerializer(many=True)
    top_rewards = RewardProgramSerializer(many=True)
    engagement_trends = serializers.ListField()
    streak_statistics = serializers.ListField()


class ReportsAnalyticsSerializer(serializers.Serializer):
    platform_usage_chart = serializers.ListField()
    health_conditions_distribution = serializers.ListField()
    available_reports = ReportSerializer(many=True)
    custom_report_types = serializers.ListField()
    date_ranges = serializers.ListField()
    formats = serializers.ListField()


    # serializers.py
from rest_framework import serializers
from .models import EducationalVideo, UserVideoInteraction, ResourceCategory

class ResourceCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ResourceCategory
        fields = ['id', 'name', 'description', 'icon']

class EducationalVideoSerializer(serializers.ModelSerializer):
    resource_category_name = serializers.CharField(source='resource_category.name', read_only=True)
    is_saved = serializers.SerializerMethodField()
    is_helpful_marked = serializers.SerializerMethodField()
    youtube_embed_url = serializers.SerializerMethodField()
    
    class Meta:
        model = EducationalVideo
        fields = [
            'id', 'title', 'description', 'youtube_url', 'youtube_embed_url',
            'thumbnail', 'resource_category', 'resource_category_name',
            'duration', 'views_count', 'helpful_count', 'saved_count',
            'target_mood', 'intensity_level', 'crisis_support_text',
            'is_professionally_reviewed', 'reviewed_by', 'review_date',
            'is_active', 'created_at', 'updated_at',
            'is_saved', 'is_helpful_marked'
        ]
        read_only_fields = [
            'views_count', 'helpful_count', 'saved_count', 'created_at', 'updated_at'
        ]
    
    def get_is_saved(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return UserVideoInteraction.objects.filter(
                user=request.user,
                video=obj,
                saved_for_later=True
            ).exists()
        return False
    
    def get_is_helpful_marked(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return UserVideoInteraction.objects.filter(
                user=request.user,
                video=obj,
                marked_helpful=True
            ).exists()
        return False
    
    def get_youtube_embed_url(self, obj):
        """Convert YouTube URL to embed URL"""
        if 'youtube.com' in obj.youtube_url:
            video_id = obj.youtube_url.split('v=')[1]
            return f'https://www.youtube.com/embed/{video_id}'
        elif 'youtu.be' in obj.youtube_url:
            video_id = obj.youtube_url.split('/')[-1]
            return f'https://www.youtube.com/embed/{video_id}'
        return obj.youtube_url
    
    def validate_youtube_url(self, value):
        """Validate that the URL is a valid YouTube URL"""
        if 'youtube.com' not in value and 'youtu.be' not in value:
            raise serializers.ValidationError("Please provide a valid YouTube URL")
        return value
    
    def validate(self, data):
        """Additional validation for mental health content"""
        if data.get('crisis_support_text') and data.get('intensity_level', 1) != 1:
            raise serializers.ValidationError(
                "Crisis support videos should have gentle intensity level (1)"
            )
        return data

class UserVideoInteractionSerializer(serializers.ModelSerializer):
    video_title = serializers.CharField(source='video.title', read_only=True)
    video_target_mood = serializers.CharField(source='video.target_mood', read_only=True)
    video_thumbnail = serializers.URLField(source='video.thumbnail', read_only=True)
    video_duration = serializers.CharField(source='video.duration', read_only=True)
    
    class Meta:
        model = UserVideoInteraction
        fields = [
            'id', 'video', 'video_title', 'video_target_mood', 'video_thumbnail', 'video_duration',
            'mood_before', 'mood_after', 'watched_full_video', 'marked_helpful',
            'saved_for_later', 'watched_at'
        ]
        read_only_fields = ['user', 'watched_at']
    
    def validate(self, data):
        """Validate mood tracking"""
        mood_before = data.get('mood_before')
        mood_after = data.get('mood_after')
        
        if mood_before and mood_after:
            if int(mood_after) < int(mood_before):
                # This is okay - sometimes people feel worse, but we might want to flag for support
                pass
        
        return data

class VideoRecommendationSerializer(serializers.ModelSerializer):
    resource_category_name = serializers.CharField(source='resource_category.name', read_only=True)
    mood_display = serializers.CharField(source='get_target_mood_display', read_only=True)
    intensity_display = serializers.CharField(source='get_intensity_level_display', read_only=True)
    
    class Meta:
        model = EducationalVideo
        fields = [
            'id', 'title', 'description', 'thumbnail', 'duration',
            'views_count', 'helpful_count', 'resource_category_name',
            'target_mood', 'mood_display', 'intensity_level', 'intensity_display'
        ]