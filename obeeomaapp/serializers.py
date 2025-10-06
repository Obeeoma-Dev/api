
# serializers.py
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.password_validation import validate_password
from obeeomaapp.models import (
    User, Organization, Client, AIManagement, HotlineActivity, ClientEngagement,
    Subscription, RecentActivity, SelfAssessment, MoodCheckIn, SelfHelpResource, ChatbotInteraction,
    UserBadge, EngagementStreak, EmployeeProfile, AvatarProfile, WellnessHub,
    AssessmentResult, EducationalResource, CrisisTrigger, Notification, EngagementTracker,
    Feedback, ChatSession, ChatMessage, RecommendationLog, MentalHealthAssessment)

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



# class LoginSerializer(serializers.Serializer):
#     username = serializers.CharField()
#     password = serializers.CharField(write_only=True)

#     def create(self, validated_data):
#         return validated_data


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
      
# Additional serializers for the new models



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