# serializers.py
from datetime import timedelta
from secrets import token_urlsafe
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from drf_spectacular.utils import extend_schema_field
from django.utils import timezone
from django.conf import settings
from rest_framework import serializers
from .models import Media
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from .models import Organization, ContactPerson
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from obeeomaapp.utils.gmail_http_api import send_gmail_api_email
from django.contrib.auth.password_validation import validate_password
from obeeomaapp.models import *
from .models import EmployeeInvitation
from .models import OnboardingState
User = get_user_model()
from rest_framework import serializers
import secrets
import string

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from obeeomaapp.models import Subscription, Billing
from django.contrib.auth import get_user_model
from django.db import transaction
import logging

User = get_user_model()
logger = logging.getLogger(__name__)

from .models import UserAchievement
import uuid
import requests
import secrets
import string
from secrets import randbelow

from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext as _

# INVITATION SERIALIZERS
class InvitationOTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, attrs):
        email = attrs.get('email')
        otp = attrs.get('otp')

        try:
            invitation = EmployeeInvitation.objects.get(
                email=email,
                otp=otp,
                accepted=False
            )

            # Check if OTP is expired
            if invitation.otp_expires_at < timezone.now():
                raise serializers.ValidationError({"otp": "OTP has expired"})

            self.context['invitation'] = invitation
            return attrs

        except EmployeeInvitation.DoesNotExist:
            raise serializers.ValidationError({"otp": "Invalid OTP or email"})


class EmployeeInvitationCreateSerializer(serializers.ModelSerializer):
    employeephone = serializers.CharField(max_length=20, required=False, allow_blank=True, help_text="Employee phone number (optional)")
    employeedepartment = serializers.CharField(max_length=100, required=False, allow_blank=True, help_text="Employee department (optional)")
    
    class Meta:
        model = EmployeeInvitation
        fields = ['email', 'message', 'employeephone', 'employeedepartment']

    def create(self, validated_data):
        employer = self.context['employer']
        user = self.context['user']

        # Generate OTP
        otp = ''.join(secrets.choice(string.digits) for _ in range(6))
        otp_expires_at = timezone.now() + timedelta(days=7)  # 7 days validity

        invitation = EmployeeInvitation.objects.create(
            employer=employer,
            invited_by=user,
            otp=otp,
            otp_expires_at=otp_expires_at,
            **validated_data
        )

        return invitation


User = get_user_model()

 # SIGNUP SERIALIZER
class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'confirm_password')

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError({"confirm_password": "Passwords don't match."})

        if User.objects.filter(username__iexact=username).exists():
            raise serializers.ValidationError({"username": "This username is already taken."})

        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')

        user = User(username=validated_data['username'])
        user.set_password(validated_data['password'])
        user.onboarding_completed = False
        user.is_first_time = True  # This allows automatic login for first time only
        user.role = "employee"  # default role for signup
        user.save()

        return user

        return user

  
# SERIALIZER FOR CREATING AN ORGANIZATION
class ContactPersonSerializer(serializers.ModelSerializer):
    firstName = serializers.CharField(source='first_name')
    lastName = serializers.CharField(source='last_name')
    role = serializers.CharField()
    email = serializers.EmailField()

    class Meta:
        model = ContactPerson
        fields = ['firstName', 'lastName', 'role', 'email']
 # Gmail OAuth helper
class OrganizationCreateSerializer(serializers.ModelSerializer):
    contactPerson = ContactPersonSerializer()
    confirmPassword = serializers.CharField(write_only=True)
    created_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Organization

        fields = [
            'organizationName',
            'organisationSize',
            'phoneNumber',
            'companyEmail',
            'Location',
            'password',
            'confirmPassword',
            'contactPerson',
            'created_at',
        ]
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        if data['password'] != data['confirmPassword']:
            raise serializers.ValidationError({"confirmPassword": "Passwords do not match."})
        validate_password(data['password'])
        return data

    def create(self, validated_data):
        contact_data = validated_data.pop('contactPerson')
        validated_data.pop('confirmPassword')

        # Create user
        user = User.objects.create(
            username=validated_data['companyEmail'],
            email=validated_data['companyEmail'],
            role='employer'
        )
        user.set_password(validated_data['password'])
        user.save()

        # Create contact person
        contact_person = ContactPerson.objects.create(**contact_data)

        # Create organization
        validated_data['password'] = make_password(validated_data['password'])
        validated_data['owner'] = user
        validated_data['contactPerson'] = contact_person
        organization = Organization.objects.create(**validated_data)

        # Send email via Gmail API (OAuth)
        
        org_email = organization.companyEmail
        org_name = organization.organizationName

        subject = "Organization Registered Successfully"
        message = (
            f"Hello {org_name},\n\n"
            f"Your organization has been successfully registered on our platform.\n\n"
            f"You can now log in using your registered organization name and password.\n\n"
            f"Thank you for registering with us!"
        )

        try:
            send_gmail_api_email(to_email=org_email, subject=subject, body=message)
        except Exception as e:
            # Log the error, but don't stop registration
            print("Failed to send email:", e)

        return organization
    
# serilaizer for organisation detials
class OrganizationDetailSerializer(serializers.ModelSerializer):
    employee_count = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = [
            'organizationName',
            'organisationSize',
            'phoneNumber',
            'companyEmail',
            'Location',
            'employee_count'
        ]

    def get_employee_count(self, obj):
        return obj.employees.count()

# Login Serializer

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if not username or not password:
            raise serializers.ValidationError('Both username and password are required.')

        # First try regular user authentication
        user = authenticate(
            request=self.context.get('request'),
            username=username,
            password=password
        )

        # This says,If regular authentication fails, try organization authentication
        if not user:
            try:
                # These lines help to Check if username matches an organization name
                from .models import Organization
                organization = Organization.objects.get(organizationName=username)
                
                # Verify the organization password
                from django.contrib.auth.hashers import check_password
                if check_password(password, organization.password):
                    if organization.owner and organization.owner.is_active:
                        user = organization.owner
                    else:
                        raise serializers.ValidationError('Organization account is not properly configured.')
                else:
                    raise serializers.ValidationError('Invalid username or password.')
                    
            except Organization.DoesNotExist:
                raise serializers.ValidationError('Invalid username or password.')

        if not user:
            raise serializers.ValidationError('Invalid username or password.')

        if not user.is_active:
            raise serializers.ValidationError('Account is not yet active.')

        attrs['user'] = user
        return attrs


# custom serializer for token obtain pair
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user

        
        data['username'] = user.username
        data['role'] = getattr(user, 'role', None)

        # Just Including only the relevant user data
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "date_joined": user.date_joined,
            "is_active": user.is_active,
            "avatar": user.avatar.url if hasattr(user, 'avatar') and user.avatar else None,
        }

        # Merge user data into the token response
        data.update({
            "user": user_data
        })
        return data

#  EmployeeOnboardingSerializer
class EmployeeOnboardingSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)
    avatar = serializers.ImageField(required=True)
    
    # Assessment fields - all required for onboarding
    gad7_scores = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=3),
        required=True,
        min_length=7,
        max_length=7,
        help_text="GAD-7 anxiety assessment: 7 scores (0-3 each)"
    )
    phq9_scores = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=3),
        required=True,
        min_length=9,
        max_length=9,
        help_text="PHQ-9 depression assessment: 9 scores (0-3 each)"
    )
    pss10_scores = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=4),
        required=True,
        min_length=10,
        max_length=10,
        help_text="PSS-10 stress assessment: 10 scores (0-4 each)"
    )

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already taken.")
        return value

    def validate(self, attrs):
        if attrs["password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return attrs

    def update(self, user, validated_data):
        # Update user profile
        user.username = validated_data["username"]
        user.set_password(validated_data["password"])
        user.avatar = validated_data["avatar"]
        user.onboarding_completed = True
        user.is_first_time = False
        user.save()
        
        # Create GAD-7 assessment
        gad7_total = sum(validated_data["gad7_scores"])
        MentalHealthAssessment.objects.create(
            user=user,
            assessment_type='GAD-7',
            gad7_scores=validated_data["gad7_scores"],
            gad7_total=gad7_total
        )
        
        # Create PHQ-9 assessment
        phq9_total = sum(validated_data["phq9_scores"])
        MentalHealthAssessment.objects.create(
            user=user,
            assessment_type='PHQ-9',
            phq9_scores=validated_data["phq9_scores"],
            phq9_total=phq9_total
        )
        
        # Create PSS-10 assessment
        pss10_total = sum(validated_data["pss10_scores"])
        # Determine stress category
        if pss10_total <= 13:
            category = "Low stress"
        elif pss10_total <= 26:
            category = "Moderate stress"
        else:
            category = "High stress"
            
        PSS10Assessment.objects.create(
            user=user,
            score=pss10_total,
            category=category
        )
        
        return user


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

# Password change serializer
class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = self.context['request'].user
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')

        # This Checks old password correctness
        if not user.check_password(old_password):
            raise serializers.ValidationError({"old_password": "Old password is incorrect."})

        # This here Prevents reuse of old password
        if old_password == new_password:
            raise serializers.ValidationError({"new_password": "New password cannot be the same as old password."})

        # Confirm match
        if new_password != confirm_password:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})

        return attrs

    def save(self, **kwargs):
        user = self.context['request'].user
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        return user

    
# Resetpasswordcomplete serializer

class ResetPasswordCompleteSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")

        try:
            user = User.objects.get(email=attrs['email'])
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found.")

        attrs['user'] = user
        return attrs


    
# SERIAILZER FOR VERIFYING RESET PASSWORD OTP
class PasswordResetOTPVerificationSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6)

    def validate(self, attrs):
        code = attrs.get("code")

        otp = PasswordResetToken.objects.filter(code=code).order_by('-created_at').first()
        if not otp:
            raise serializers.ValidationError("Invalid verification code.")

        if otp.expires_at < timezone.now():
            otp.delete()
            raise serializers.ValidationError("This OTP has expired. Please request a new one.")

        self.context["user"] = otp.user
        self.context["otp"] = otp
        return attrs





# SERIALIZERS FOR MFA SETUP AND VERIFICATION

# MFA Setup Serializer
# mfa_setup view doesn't require any input fields, because the superuser is already logged in. 
# We'll keep it empty but define it for consistency.
class MFASetupSerializer(serializers.Serializer):
    pass  # no fields required


# This is Used to confirm MFA after setup
class MFAConfirmSerializer(serializers.Serializer):
    code = serializers.CharField(
        max_length=6,
        required=True,
        help_text="6-digit MFA code from your authenticator app"
    )

# Used during login to verify MFA code
class MFAVerifySerializer(serializers.Serializer):
    temp_token = serializers.CharField(
        required=True,
        help_text="Temporary token received after login step 1"
    )
    code = serializers.CharField(
        max_length=6,
        required=True,
        help_text="6-digit MFA code from your authenticator app"
    )

#  MFA PasswordVerify Serializer
class MFAPasswordVerifySerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)

#MFA Toggle Serializer
class MFAToggleSerializer(serializers.Serializer):
    mfa_enabled = serializers.BooleanField()
    mfa_settings_token = serializers.CharField()


# USER SERIALIZER
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
    name = serializers.CharField(read_only=True)

    class Meta:
        model = Employee
        fields = ['id', 'employer', 'employer_name', 'department', 'department_name', 'first_name', 'last_name', 'name', 'email', 'status', 'joined_date', 'last_active', 'avatar']


class NotificationSerializer(serializers.ModelSerializer):
    is_read = serializers.BooleanField(source='read', read_only=True)  # Add this field
    
    class Meta:
        model = Notification
        fields = ['id', 'employee', 'message', 'sent_on', 'read', 'is_read']  # Include both
        read_only_fields = ['employee', 'sent_on']

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
        fields = ['id', 'employer', 'plan', 'amount', 'seats', 'start_date', 'end_date', 'is_active']


class RecentActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = RecentActivity
        fields = ['id', 'employer', 'activity_type', 'details', 'timestamp', 'is_important']


class SelfAssessmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = SelfAssessment
        fields = ['id', 'user', 'assessment_type', 'score', 'submitted_at']

class MoodTrackingSerializer(serializers.ModelSerializer):
    class Meta:
        model = MoodTracking
        fields = ['id', 'mood',  'checked_in_at']
        read_only_fields = ['id', 'checked_in_at']

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


class EmployeeUserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['email', 'user_name', 'password', 'password_confirm']
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password_confirm": "Passwords don't match"})
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(
            username=validated_data['email'],  # Use email as username
            email=validated_data['email'],
            password=validated_data['password'],
    
            is_active=True
        )
        return user





# --- Employee Profile ---


class EmployeeProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployeeProfile
        exclude = ['user', 'joined_on']  # Exclude these from input

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
   


# --- Avatar ---
class AvatarProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = AvatarProfile
        fields = '__all__'
        read_only_fields = ['employee']




class AssessmentResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssessmentResult
        fields = '__all__'
        read_only_fields = ['employee', 'submitted_on']


class EducationalResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = EducationalResource
        fields = '__all__'


class CrisisTriggerSerializer(serializers.ModelSerializer):
    class Meta:
        model = CrisisTrigger
        fields = '__all__'
        read_only_fields = ['employee', 'triggered_on']

class EngagementTrackerSerializer(serializers.ModelSerializer):
    class Meta:
        model = EngagementTracker
        fields = '__all__'
        read_only_fields = ['employee']

class FeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feedback
        fields = '__all__'
        read_only_fields = ['employee', 'submitted_on']


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


class RecommendationLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecommendationLog
        fields = '__all__'
        read_only_fields = ['employee', 'recommended_on']




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
    name = serializers.CharField(read_only=True)

    class Meta:
        model = Employee
        fields = ['id', 'first_name', 'last_name', 'name', 'email', 'department', 'department_name', 'status', 'status_display', 'joined_date', 'avatar']

# subscription Management Serializer
class SubscriptionManagementSerializer(serializers.ModelSerializer):
    plan_details = SubscriptionPlanSerializer(read_only=True)
    payment_method = PaymentMethodSerializer(read_only=True)
    available_seats = serializers.ReadOnlyField()
    
    class Meta:
        model = Subscription
        fields = ['id', 'plan', 'plan_details', 'amount', 'seats', 'used_seats', 'available_seats', 'start_date', 'renewal_date', 'is_active', 'payment_method']


# PAYMENT VERIFICATION SERIALIZER
class PaymentVerificationSerializer(serializers.Serializer):
   
    tx_ref = serializers.CharField(
        max_length=255, 
        help_text="Flutterwave transaction reference (tx_ref) for verification."
    )
    subscription_id = serializers.IntegerField(
        help_text="The ID of the subscription object created during payment initiation."

    )
# SUBSCRIPTION INITIATE SERIALIZER
class SubscriptionInitiateSerializer(serializers.Serializer):
    """
    Validates input data and fetches the associated SubscriptionPlan object.
    """
    plan_id = serializers.CharField(
        max_length=50, 
        required=True,
        help_text="The ID (e.g., 'enterprise') of the subscription plan."
    )

    def validate_plan_id(self, value):
        """
        Ensures the plan_id corresponds to an existing and active SubscriptionPlan.
        """
        try:
            # The 'plan_id' from the request matches the 'id' field of the SubscriptionPlan model.
            selected_plan = SubscriptionPlan.objects.get(id=value, is_active=True)
            
            # Attach the found plan object to the serializer instance for easy access in the view
            self.selected_plan = selected_plan 
            
            return value
        
        except ObjectDoesNotExist:
            raise serializers.ValidationError(_("The selected subscription plan is invalid or not currently available."))


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


# CrisisHotlineSerializer
class CrisisHotlineSerializer(serializers.ModelSerializer):
    class Meta:
        model = CrisisHotline
        fields = ['id', 'country', 'region', 'hotline_name', 'phone_number', 'is_active']


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
    
    @extend_schema_field(int)
    def get_client_count(self, obj) -> int:
        return obj.employees.count()
    
    @extend_schema_field(str)
    def get_current_plan(self, obj) -> str:
        active_subscription = obj.subscriptions.filter(is_active=True).first()
        return active_subscription.plan if active_subscription else "No active plan"
    
    class Meta:
        model = Employer
        fields = ['id', 'name', 'client_count', 'current_plan', 'is_active', 'status_display', 'joined_date']

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

from rest_framework import serializers
from .models import (
    Video, EducationalResource, Audio, Article, 
    MeditationTechnique, SavedResource, UserActivity,
    OnboardingState, DynamicQuestion, Notification
)

# # Video Recommendation Serializer
# class VideoRecommendationSerializer(serializers.ModelSerializer):
#     resource_category_name = serializers.CharField(source='resource_category.name', read_only=True)
#     mood_display = serializers.CharField(source='get_target_mood_display', read_only=True)
#     intensity_display = serializers.CharField(source='get_intensity_level_display', read_only=True)
#     thumbnail = serializers.SerializerMethodField() 
#     class Meta:
#         model = Video
#         fields = [
#             'id', 'title', 'description', 'thumbnail', 'duration',
#             'views_count', 'helpful_count', 'resource_category_name',
#             'target_mood', 'mood_display', 'intensity_level', 'intensity_display',
#         ]

# Educational Resource Serializer
class EducationalResourceSerializer(serializers.ModelSerializer):
    video_count = serializers.SerializerMethodField()
    audio_count = serializers.SerializerMethodField()
    article_count = serializers.SerializerMethodField()
    meditation_count = serializers.SerializerMethodField()

    class Meta:
        model = EducationalResource
        fields = '__all__'

    @extend_schema_field(serializers.IntegerField())
    def get_video_count(self, obj) -> int:
        return obj.videos.filter(is_active=True).count()

    @extend_schema_field(serializers.IntegerField())
    def get_audio_count(self, obj) -> int:
        return obj.audios.filter(is_active=True).count()

    @extend_schema_field(serializers.IntegerField())
    def get_article_count(self, obj) -> int:
        return obj.articles.filter(is_published=True).count()

    @extend_schema_field(serializers.IntegerField())
    def get_meditation_count(self, obj) -> int:
        return obj.meditations.filter(is_active=True).count()

# Video Serializer
class VideoSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)
    is_saved = serializers.SerializerMethodField()

    class Meta:
        model = Video
        fields = [
            'id', 'title', 'category', 'category_name', 'duration', 
            'target_mood', 'views', 'is_active', 'created_at', 'updated_at',
            'reviewed_by', 'review_date', 'views_count', 'helpful_count', 
            'saved_count', 'is_saved'
        ]
        extra_kwargs = {
            'category': {'required': False, 'allow_null': True}
        }
        read_only_fields = ['views', 'views_count']

    @extend_schema_field(serializers.BooleanField())
    def get_is_saved(self, obj) -> bool:
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return SavedResource.objects.filter(user=request.user, video=obj).exists()
        return False

# Audio Serializer
class AudioSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)
    is_saved = serializers.SerializerMethodField()
    audio_url_full = serializers.SerializerMethodField()

    class Meta:
        model = Audio
        fields = [
            'id', 'title', 'description',  'audio_url',
            'audio_url_full',  'category_name', 'duration',
            'plays', 'is_saved', 'created_at'
        ]
        extra_kwargs = {
            'category': {'required': False, 'allow_null': True}
        }
        read_only_fields = ['plays']

    @extend_schema_field(serializers.BooleanField())
    def get_is_saved(self, obj) -> bool:
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return SavedResource.objects.filter(user=request.user, audio=obj).exists()
        return False

    @extend_schema_field(serializers.URLField())
    def get_audio_url_full(self, obj) -> str:
        if obj.audio_file:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.audio_file.url)
        return obj.audio_url

# Article Serializer
class ArticleSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)
    author_name = serializers.CharField(source='Title.username', read_only=True, allow_null=True)
    is_saved = serializers.SerializerMethodField()

    class Meta:
        model = Article
        fields = '__all__'
        read_only_fields = ['views']

    @extend_schema_field(serializers.BooleanField())
    def get_is_saved(self, obj) -> bool:
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return SavedResource.objects.filter(user=request.user, article=obj).exists()
        return False
# Meditation Technique Serializer

class MeditationTechniqueSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)
    difficulty_display = serializers.CharField(source='get_difficulty_display', read_only=True)
    is_saved = serializers.SerializerMethodField()

    class Meta:
        model = MeditationTechnique
        fields = '__all__'
        read_only_fields = ['times_practiced']

    @extend_schema_field(serializers.BooleanField())
    def get_is_saved(self, obj) -> bool:
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return SavedResource.objects.filter(user=request.user, meditation=obj).exists()
        return False


# Saved Resource Serializer

class SavedResourceSerializer(serializers.ModelSerializer):
    resource_type = serializers.SerializerMethodField()
    resource_title = serializers.SerializerMethodField()

    class Meta:
        model = SavedResource
        fields = [
            'id', 'video', 'cbt_exercise', 'article', 'meditation',
            'resource_type', 'resource_title', 'saved_at'
        ]

    @extend_schema_field(serializers.CharField())
    def get_resource_type(self, obj) -> str:
        if obj.video:
            return 'video'
        elif obj.cbt_exercise:
            return 'cbt_exercise'
        elif obj.audio:
            return 'audio'
        elif obj.article:
            return 'article'
        elif obj.meditation:
            return 'meditation'
        return 'unknown'

    @extend_schema_field(serializers.CharField())
    def get_resource_title(self, obj) -> str:
        if obj.video:
            return obj.video.title
        elif obj.cbt_exercise:
            return obj.cbt_exercise.title
        elif obj.audio:
            return obj.audio.title
        elif obj.article:
            return obj.article.title
        elif obj.meditation:
            return obj.meditation.title
        return 'Unknown'
# User Activity Serializer
class UserActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserActivity
        fields = [
            'id', 'video', 'cbt_exercise', 'article', 'meditation', 'audio',
            'completed', 'progress_percentage', 'notes', 'accessed_at'
        ]

# Onboarding State Serializer
class OnboardingStateSerializer(serializers.ModelSerializer):
    class Meta:
        model = OnboardingState
        fields = ['goal', 'completed', 'first_action_done']

# Dynamic Question Serializer
class DynamicQuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = DynamicQuestion
        fields = ['id', 'text', 'category', 'is_active', 'created_at']


# ===== ASSESSMENT QUESTIONNAIRE SERIALIZERS =====

class AssessmentQuestionSerializer(serializers.ModelSerializer):
    """Serializer for assessment questions"""
    assessment_type_display = serializers.CharField(source='get_assessment_type_display', read_only=True)
    
    class Meta:
        model = AssessmentQuestion
        fields = ['id', 'assessment_type', 'assessment_type_display', 'question_number', 'question_text']


class AssessmentResponseSerializer(serializers.ModelSerializer):
    """Serializer for submitting assessment responses"""
    severity_level = serializers.CharField(read_only=True)
    recommendations = serializers.SerializerMethodField()
    assessment_type_display = serializers.CharField(source='get_assessment_type_display', read_only=True)
    
    class Meta:
        model = AssessmentResponse
        fields = [
            'id', 'assessment_type', 'assessment_type_display', 'responses',
            'total_score', 'severity_level', 'difficulty_level',
            'recommendations', 'completed_at'
        ]
        read_only_fields = ['total_score', 'severity_level', 'completed_at']
    
    def validate_responses(self, value):
        """Validate responses array"""
        assessment_type = self.initial_data.get('assessment_type')
        
        if not isinstance(value, list):
            raise serializers.ValidationError("Responses must be an array of scores.")
        
        # Check length
        if assessment_type == 'PHQ-9' and len(value) != 9:
            raise serializers.ValidationError("PHQ-9 requires exactly 9 responses.")
        elif assessment_type == 'GAD-7' and len(value) != 7:
            raise serializers.ValidationError("GAD-7 requires exactly 7 responses.")
        
        # Check each score is 0-3
        for score in value:
            if not isinstance(score, int) or score < 0 or score > 3:
                raise serializers.ValidationError("Each response must be a score between 0 and 3.")
        
        return value
    
    @extend_schema_field(serializers.ListField(child=serializers.CharField()))
    def get_recommendations(self, obj) -> list:
        return obj.get_recommendations()


class AssessmentResultSerializer(serializers.Serializer):
    """Serializer for assessment results"""
    assessment_type = serializers.CharField()
    total_score = serializers.IntegerField()
    severity_level = serializers.CharField()
    severity_description = serializers.CharField()
    recommendations = serializers.ListField(child=serializers.CharField())
    completed_at = serializers.DateTimeField()
    score_breakdown = serializers.DictField()


class AssessmentQuestionsResponseSerializer(serializers.Serializer):
    """Serializer for questions endpoint response"""
    assessment_type = serializers.CharField()
    title = serializers.CharField()
    description = serializers.CharField()
    instructions = serializers.CharField()
    time_frame = serializers.CharField()
    questions = AssessmentQuestionSerializer(many=True)
    score_options = serializers.ListField()
    difficulty_question = serializers.CharField()
    difficulty_options = serializers.ListField()


class UserAchievementSerializer(serializers.ModelSerializer):
    title = serializers.CharField(source='achievement.title')
    description = serializers.CharField(source='achievement.description')
    category = serializers.CharField(source='achievement.category')
    target_count = serializers.IntegerField(source='achievement.target_count')
    progress_percentage = serializers.SerializerMethodField()

    class Meta:
        model = UserAchievement
        fields = [
            'title', 'description', 'category',
            'progress_count', 'target_count',
            'progress_percentage', 'achieved', 'achieved_date'
        ]

    def get_progress_percentage(self, obj):
        return obj.progress_percentage()


# ADMIN USER MANAGEMENT SERIALIZER
class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ['id', 'name', 'size', 'phone', 'email', 'location', 'created_at']


class AdminUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'password',
            'role', 'organization', 'onboarding_completed',
            'is_suspended', 'avatar', 'is_active'
        ]
        read_only_fields = ['is_active']  # deactivation handled by action

    def validate(self, attrs):
        role = attrs.get('role', getattr(self.instance, 'role', None))

        # If creating/updating an employer, ensure organization exists
        if role == 'employer':
            org = attrs.get('organization') or getattr(self.instance, 'organization', None)
            if not org:
                raise serializers.ValidationError("Employer must belong to an organization.")

        # If role is employee, avatar must be present when creating or when trying to activate
        avatar = attrs.get('avatar', getattr(self.instance, 'avatar', None))
        if role == 'employee' and not avatar and not getattr(self.instance, 'avatar', None):
            # If creating a new employee, require avatar
            if not self.instance:
                raise serializers.ValidationError("Employee must have an avatar.")
            # If updating and the employee is being (re)activated, enforce avatar
            if attrs.get('is_active') is True:
                raise serializers.ValidationError("Employee must have an avatar before activation.")
        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User(**validated_data)
        # Employees are created with onboarding_completed=False by default
        user.onboarding_completed = validated_data.get('onboarding_completed', False)
        user.set_password(password or User.objects.make_random_password())
        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        instance.save()
        return instance
class AdminSubscriptionSerializer(serializers.ModelSerializer):
    """
    Serializer used by SYSTEM ADMIN
    to view and manage ALL subscriptions
    across ALL organizations.
    """

    class Meta:
        model = Subscription
        fields = '__all__'
        read_only_fields = [
            'id',
            'created_at',
            'updated_at'
        ]


class AdminBillingSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for SYSTEM ADMIN
    to audit billing records (payments, invoices, etc).
    """

    class Meta:
        model = Billing
        fields = '__all__'
        read_only_fields = fields  # billing history should not be edited


    
# SETTINGS
class SettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Settings
        fields = ['id', 'user', 'dark_mode', 'notifications_enabled', 'email_updates']
        read_only_fields = ['user']    

# Media upload serializer for systems admin.
class MediaSerializer(serializers.ModelSerializer):
    uploaded_by = serializers.StringRelatedField(read_only=True)
    file = serializers.FileField(required=False, allow_null=True)
    thumbnail = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = Media
        fields = [
            'id', 'media_type', 'title', 'description', 'body', 'file', 'thumbnail',
            'duration_seconds', 'tags', 'uploaded_by', 'is_published', 'published_at',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['uploaded_by', 'created_at', 'updated_at']

    def validate(self, data):
        media_type = data.get('media_type') or self.instance.media_type if getattr(self, 'instance', None) else None

        # Article must have body; should NOT require file
        if media_type == Media.ARTICLE:
            body = data.get('body') if 'body' in data else getattr(self.instance, 'body', '')
            if not body:
                raise serializers.ValidationError("Article must include a body/text.")
        else:
            # audio or video must have file
            file = data.get('file') if 'file' in data else getattr(self.instance, 'file', None)
            if not file:
                raise serializers.ValidationError("Audio and Video items must include a file upload.")

        return data

    def create(self, validated_data):
        request = self.context.get('request')
        if request and request.user and request.user.is_authenticated:
            validated_data['uploaded_by'] = request.user

        # If publishing now and no published_at set, set timestamp
        if validated_data.get('is_published') and not validated_data.get('published_at'):
            validated_data['published_at'] = timezone.now()

        return super().create(validated_data)

    def update(self, instance, validated_data):
        # same publish behavior
        if validated_data.get('is_published') and not instance.published_at:
            validated_data['published_at'] = timezone.now()
        return super().update(instance, validated_data)
    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user

class CBTExerciseSerializer(serializers.ModelSerializer):
    class Meta:
        model = CBTExercise
        fields = '__all__'
        ready_only_fields = ['user', 'created_at', 'updated_at']
class JournalEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = JournalEntry
        fields = '__all__'    
        read_only_fields = ['user', 'created_at', 'updated_at']   

# Payment Token Serializer
class PaymentTokenSerializer(serializers.Serializer):
    """
    Serializer for validating the tokenization response sent from the frontend 
    after a successful Flutterwave callback.
    """
    token_id = serializers.CharField(
        max_length=255,
        required=True,
        help_text="The secure card token generated by Flutterwave."
    )
    # The email is used by the frontend for the Flutterwave modal, 
    # but the backend should use the authenticated user for security.
    # We include it here if the view needs to cross-reference it.
    email = serializers.EmailField(
        required=False,
        help_text="User email (optional, primarily for debugging/cross-reference)."
    )

    # for better record-keeping (e.g., last_4_digits, card_type)
    card_last_four = serializers.CharField(max_length=4, required=False)
    card_type = serializers.CharField(max_length=50, required=False)
    expiry_month = serializers.IntegerField(min_value=1, max_value=12, required=False)
    expiry_year = serializers.IntegerField(min_value=2020, required=False)

    class Meta:
        pass

from rest_framework import serializers

class PSS10AssessmentSerializer(serializers.ModelSerializer):
    responses = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=4),
        min_length=10,
        max_length=10
    )
    
    class Meta:
        model = PSS10Assessment
        fields = ['id', 'user', 'score', 'category', 'responses', 'created_at']
        read_only_fields = ['id', 'user', 'score', 'category', 'created_at']



# content/serializers.py
from rest_framework import serializers
from .models import ContentArticle, ContentMedia

class ContentArticleSerializer(serializers.ModelSerializer):
    author = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = ContentArticle
        fields = ["id", "title", "body", "author", "published", "created_at", "updated_at"]
        read_only_fields = ["id", "author", "created_at", "updated_at"]


class ContentMediaSerializer(serializers.ModelSerializer):
    owner = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = ContentMedia
        fields = [
            "id",
            "title",
            "description",
            "media_type",
            "s3_key",
            "public_url",
            "duration_seconds",
            "uploaded",
            "processed",
            "owner",
            "created_at",
        ]
        read_only_fields = ["id", "s3_key", "public_url", "uploaded", "processed", "owner", "created_at"]


# New serializers for the requested endpoints

class EngagementLevelSerializer(serializers.ModelSerializer):
    activeEmployees = serializers.SerializerMethodField()
    inactiveEmployees = serializers.SerializerMethodField()
    totalEmployees = serializers.SerializerMethodField()

    class Meta:
        model = EngagementLevel
        fields = ['id', 'worker_department', 'hours_engaged', 'recorded_at', 'activeEmployees', 'inactiveEmployees', 'totalEmployees']

    def get_activeEmployees(self, obj):
        return Employee.objects.filter(status='active').count()

    def get_inactiveEmployees(self, obj):
        return Employee.objects.filter(status__in=['inactive', 'suspended']).count()

    def get_totalEmployees(self, obj):
        return Employee.objects.count()


class CompanyMoodSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyMood
        fields = ['id', 'summary_description', 'created_at']


class WellnessGraphSerializer(serializers.ModelSerializer):
    class Meta:
        model = WellnessGraph
        fields = ['id', 'user', 'mood_score', 'mood_date']




class EmployeeManagementSerializer(serializers.ModelSerializer):
    empemail = serializers.EmailField(source='email')
    empdepartment = serializers.CharField(source='department.name', read_only=True)
    empstatus = serializers.CharField(source='status')

    class Meta:
        model = Employee
        fields = ['id', 'empemail', 'empdepartment', 'empstatus']

# content/serializers.py
from rest_framework import serializers
from .models import ContentArticle, ContentMedia

class ContentArticleSerializer(serializers.ModelSerializer):
    author = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = ContentArticle
        fields = ["id", "title", "body", "author", "published", "created_at", "updated_at"]
        read_only_fields = ["id", "author", "created_at", "updated_at"]


class ContentMediaSerializer(serializers.ModelSerializer):
    owner = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = ContentMedia
        fields = [
            "id",
            "title",
            "description",
            "media_type",
            "s3_key",
            "public_url",
            "duration_seconds",
            "uploaded",
            "processed",
            "owner",
            "created_at",
        ]
        read_only_fields = ["id", "s3_key", "public_url", "uploaded", "processed", "owner", "created_at"]
