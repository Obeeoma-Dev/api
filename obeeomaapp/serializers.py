
# serializers.py
from rest_framework.exceptions import AuthenticationFailed

from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.password_validation import validate_password
from obeeomaapp.models import (
    User, Employer, Employee, AIManagement, HotlineActivity, EmployeeEngagement,
    Subscription, RecentActivity, SelfAssessment, MoodCheckIn, SelfHelpResource, ChatbotInteraction,
    UserBadge, EngagementStreak, EmployeeProfile, AvatarProfile, WellnessHub,
    AssessmentResult, EducationalResource, CrisisTrigger, Notification, EngagementTracker,
    Feedback, ChatSession, ChatMessage, RecommendationLog, MentalHealthAssessment, EmployeeInvitation
    )

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
    class Meta:
        model = Employee
        fields = ['id', 'employer', 'name', 'email', 'joined_date']


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

