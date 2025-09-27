from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from obeeomaapp.models import *

User = get_user_model()

# --- Auth & User ---
class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'confirm_password')

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords don’t match."})
        return attrs

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'avatar', 'onboarding_completed']


# --- Core Models ---
class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'


class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = ['id', 'organization', 'name', 'email', 'joined_date']


class AIManagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIManagement
        fields = ['id', 'organization', 'title', 'description', 'effectiveness', 'created_at']


class HotlineActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = HotlineActivity
        fields = ['id', 'organization', 'call_count', 'spike_percentage', 'recorded_at']


class ClientEngagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientEngagement
        fields = ['id', 'organization', 'engagement_rate', 'month', 'notes']


class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = ['id', 'organization', 'plan', 'Subscriptions', 'start_date', 'end_date', 'is_active']


class RecentActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = RecentActivity
        fields = ['id', 'organization', 'activity_type', 'details', 'timestamp', 'is_important']


# --- Mental Health ---
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


# --- Gamification ---
class UserBadgeSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserBadge
        fields = ['id', 'user', 'badge_name', 'awarded_on']


class EngagementStreakSerializer(serializers.ModelSerializer):
    class Meta:
        model = EngagementStreak
        fields = ['id', 'user', 'current_streak', 'last_check_in']


# --- Analytics & Crisis Support ---
class AnalyticsSnapshotSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalyticsSnapshot
        fields = ['id', 'organization', 'date', 'active_users', 'average_stress_score', 'most_used_feature']


class CrisisHotlineSerializer(serializers.ModelSerializer):
    class Meta:
        model = CrisisHotline
        fields = ['id', 'country', 'region', 'hotline_name', 'phone_number', 'is_active']


# --- Admin Monitoring ---
class AuthenticationEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthenticationEvent
        fields = ['id', 'user', 'event_type', 'ip_address', 'timestamp']


class AdminActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminAction
        fields = ['id', 'performed_by', 'target_user', 'action_type', 'reason', 'timestamp']


class FeatureFlagSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeatureFlag
        fields = ['id', 'name', 'description', 'enabled', 'updated_at']


class SystemStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemStatus
        fields = ['id', 'is_in_maintenance', 'message', 'updated_at']
