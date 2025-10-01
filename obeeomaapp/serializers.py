
# serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from obeeomaapp.models import *

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

        # Automatically create a Client record if the role is employee
        if role == 'employee':
            Client.objects.create(
                user=user,
                name=user.username,
                email=user.email,
                organization=None  # or assign default org if needed
            )

        return user



class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def create(self, validated_data):
        return validated_data


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
        fields = ['id', 'organization', 'plan', 'amount', 'start_date', 'end_date', 'is_active']


class RecentActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = RecentActivity
        fields = ['id', 'organization', 'activity_type', 'details', 'timestamp', 'is_important']


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


# Response serializers for APIView GET responses
class OverviewResponseSerializer(serializers.Serializer):
    organization_count = serializers.IntegerField()
    client_count = serializers.IntegerField()
    active_subscriptions = serializers.IntegerField()
    recent_activities = RecentActivitySerializer(many=True)


class TrendsResponseSerializer(serializers.Serializer):
    hotline_trends = HotlineActivitySerializer(many=True)


class ClientEngagementResponseSerializer(serializers.Serializer):
    engagements = ClientEngagementSerializer(many=True)


class FeaturesUsageResponseSerializer(serializers.Serializer):
    ai_managements = AIManagementSerializer(many=True)


class BillingResponseSerializer(serializers.Serializer):
    subscriptions = SubscriptionSerializer(many=True)
    total_revenue = serializers.FloatField()


class UsersResponseSerializer(serializers.Serializer):
    clients = ClientSerializer(many=True)


class UserDetailResponseSerializer(serializers.Serializer):
    client = ClientSerializer()


class ReportsResponseSerializer(serializers.Serializer):
    reports = RecentActivitySerializer(many=True)


class CrisisInsightsResponseSerializer(serializers.Serializer):
    hotline_data = HotlineActivitySerializer(many=True)
      