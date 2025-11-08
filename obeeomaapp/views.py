# Keep only these imports (external modules)
from django.http import JsonResponse
from django.db.models import Avg, Count, Sum
from rest_framework.decorators import action
from .serializers import LogoutSerializer
from drf_spectacular.utils import extend_schema
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate, get_user_model
from rest_framework import status, permissions, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from drf_spectacular.utils import extend_schema, OpenApiParameter
from .models import OnboardingState
from .serializers import OnboardingStateSerializer
from rest_framework.permissions import (
    IsAuthenticated,
    BasePermission,
    IsAuthenticatedOrReadOnly,
    AllowAny,
)


from drf_spectacular.utils import extend_schema_view, extend_schema
from django.db.models import Avg

from .models import Feedback
from .serializers import FeedbackSerializer
import logging

logger = logging.getLogger(__name__)
from django.db.models import Avg
from rest_framework import viewsets, permissions, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from drf_spectacular.types import OpenApiTypes
from django_filters.rest_framework import DjangoFilterBackend, FilterSet, CharFilter
from drf_spectacular.utils import extend_schema, extend_schema_view

from .models import Feedback
from .serializers import FeedbackSerializer
import django_filters
from .models import Feedback 
from .models import DynamicQuestion
from .serializers import DynamicQuestionSerializer
import random
from rest_framework import viewsets, permissions, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import (
    extend_schema, extend_schema_view, OpenApiParameter
)

from rest_framework.generics import RetrieveUpdateAPIView, UpdateAPIView
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import *  
from django.core.mail import send_mail, EmailMultiAlternatives
from .utils.gmail_http_api import send_gmail_api_email
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import secrets
from rest_framework import filters
import string
import pyotp, qrcode, io, base64
from django.utils.crypto import get_random_string
from django.core.cache import cache
from .models import Organization
from .serializers import OTPVerificationSerializer
from .serializers import OrganizationCreateSerializer
from django.template.loader import render_to_string
from django.contrib.auth import authenticate, login as django_login

import logging
from django_filters.rest_framework import DjangoFilterBackend
from .serializers import (
    EmployeeProfileSerializer
)


# Set up logging
logging.getLogger(__name__)

# Get User model
User = get_user_model()

#Permission: company admin (is_staff) 
class IsCompanyAdmin(BasePermission):
    """Allows access only to users with is_staff=True."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_staff)


# Authentication Views ---Signup
@extend_schema(tags=['Authentication'])
class SignupView(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = SignupSerializer
    permission_classes = [permissions.AllowAny]

# VIEWS FOR CREATING AN ORGANIZATION
@extend_schema(
    tags=['Authentication'],
    request=OrganizationCreateSerializer,
    responses={201: OrganizationCreateSerializer}
)
class OrganizationSignupView(viewsets.ModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationCreateSerializer
    permission_classes = [permissions.AllowAny]

# VIEWS FOR VERIFYING THE OTP
class VerifyOTPView(APIView):
    @extend_schema(
        request=OTPVerificationSerializer,
        responses=OTPVerificationSerializer  
    )
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.context['user']
        # This helps the system to Delete OTPs to prevent reuse
        user.passwordresetotp_set.all().delete()

        return Response(
            {"message": "OTP verified successfully. You can now reset your password."},
            status=status.HTTP_200_OK
        )


# login view
@extend_schema(
    request=LoginSerializer,          
    responses={200: OpenApiTypes.OBJECT},
    tags=['Authentication'],
    description="Login using username and password only."
)
@extend_schema(
    request=LoginSerializer,
    responses={200: OpenApiTypes.OBJECT},
    tags=['Authentication'],
    description="Login using username and password. MFA integrated if enabled."
)

# LOGIN VIEW
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer
    queryset = None

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']

    # This is for MFA Check 
        if user.mfa_enabled:
            # this logic Generates temporary token for MFA verification
            temp_token = get_random_string(32)
            cache.set(temp_token, user.id, timeout=300)  # valid 5 minutes
            return Response({
                "mfa_required": True,
                "temp_token": temp_token
            })

# This is our Normal login 
        refresh = RefreshToken.for_user(user)

        display_username = user.username
        try:
            organization = user.organizations.first()
            if organization:
                display_username = organization.organizationName
        except:
            pass

        user_data = {
            "id": user.id,
            "username": display_username,
            "email": user.email,
            "role": user.role,
            "date_joined": user.date_joined,
            "is_active": user.is_active,
            "avatar": user.avatar.url if hasattr(user, 'avatar') and user.avatar else None,
        }

        if user.role == 'systemadmin':
            redirect_url = '/admin/dashboard/'
        elif user.role in ['organization', 'employer']:
            redirect_url = '/organization/dashboard/'
        elif user.role == 'employee':
            redirect_url = '/api/v1/mobile-login-success/'
        else:
            redirect_url = '/'

        # Log the user in (this creates session cookie if needed)
        django_login(request, user)

        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": user_data,
            "redirect_url": redirect_url
        })
    
# matching view for custom token obtain pair serializer
@extend_schema(
    tags=['Authentication'],
    request=CustomTokenObtainPairSerializer,
    responses={200: CustomTokenObtainPairSerializer}
)
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    

# LOGOUT VIEW
@extend_schema(
    tags=["Authentication"],
    request=LogoutSerializer,
    responses={205: {"description": "Logged out successfully"}, 400: {"description": "Invalid or expired token"}},
)
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data["refresh"]
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"message": "Logged out successfully."},
                status=status.HTTP_205_RESET_CONTENT
            )
        except Exception:
            return Response(
                {"error": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST
            )


# password reset request view
@extend_schema(tags=['Authentication'])
class PasswordResetView(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetSerializer

    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")

        user = User.objects.filter(email=email).first()
        if not user:
            return Response(
                {"message": f"If an account exists for {email}, a reset code has been sent."},
                status=status.HTTP_200_OK
            )

        try:
            code = ''.join(secrets.choice(string.digits) for _ in range(6))
            token = secrets.token_urlsafe(32)
            expires_at = timezone.now() + timedelta(minutes=5)

            PasswordResetToken.objects.filter(user=user).delete()

            reset_token = PasswordResetToken.objects.create(
                user=user,
                token=token,
                code=code,
                expires_at=expires_at
            )
        except Exception as e:
            logger.error("Error generating password reset token: %s", str(e))
            return Response(
                {"error": "Something went wrong while generating reset token."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Send email using Gmail API
        subject = "Password Reset Verification Code - Obeeoma"
        message = f"""
Hello {user.username},

You requested a password reset for your Obeeoma account.

Your verification code is: {code}

This code will expire in 5 minutes.

If you did not request this password reset, please ignore this email.

Best regards,
Obeeoma Team
"""

        try:
            success = send_gmail_api_email(email, subject, message)
            if not success:
                raise Exception("Gmail API failed to send email")

            return Response(
                {
                    "message": f"If an account exists for {email}, a reset code has been sent.",
                    "token": token
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error("Error sending password reset email: %s", str(e))
            reset_token.delete()
            return Response(
                {"error": "Failed to send email. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# Confirm Password Reset View
@extend_schema(tags=['Authentication'])
class PasswordResetConfirmView(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetSerializer

    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        code = serializer.validated_data['code']
        new_password = serializer.validated_data['new_password']
        
        # Get token from request headers or body
        token = request.data.get('token')
        if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # This part checks if token and code are valid
            reset_token = PasswordResetToken.objects.get(
                token=token,
                code=code,
                is_used=False
            )
            
            # This part checks if token is expired
            if reset_token.is_expired():
                reset_token.delete()
                return Response({"error": "Verification code has expired"}, status=status.HTTP_400_BAD_REQUEST)
            
            # This helps in Updating user password
            user = reset_token.user
            user.set_password(new_password)
            user.save()
            
            # Mark token as used
            reset_token.mark_as_used()
            
            return Response({
                "message": "Password reset successfully"
            }, status=status.HTTP_200_OK)
            
        except PasswordResetToken.DoesNotExist:
            return Response({"error": "Invalid verification code"}, status=status.HTTP_400_BAD_REQUEST)

# View for changing or updating password
@extend_schema(tags=['Authentication'])
class PasswordChangeView(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordChangeSerializer

    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        new_password = serializer.validated_data['new_password']

        # This logic helps in Setting a new password
        user.set_password(new_password)
        user.save()

        return Response(
            {"message": "Password updated successfully"},
            status=status.HTTP_200_OK
        )



# This is the Setup for MFA (when the superuser is already logged in)
@extend_schema(request=MFASetupSerializer, responses={200: MFASetupSerializer})
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mfa_setup(request):
    user = request.user
    if not user.is_superuser:
        return Response({'error': 'Only superadmin can enable MFA'}, status=403)

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    otpauth_uri = totp.provisioning_uri(
        name=user.username,
        issuer_name="ObeeomaApp"
    )

    # This helps the system to Generate the QR image in base64
    qr = qrcode.make(otpauth_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    user.set_mfa_secret(secret)
    user.save()

    return Response({
        "otpauth_uri": otpauth_uri,
        "qr_code_base64": qr_b64
    })


# This setup comfirms the MFA

@extend_schema(request=MFAConfirmSerializer, responses={200: MFAConfirmSerializer}) 
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mfa_confirm(request):
    user = request.user
    code = request.data.get("code")

    secret = user.get_mfa_secret()
    if not secret:
        return Response({"error": "MFA not initialized"}, status=400)

    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        user.mfa_enabled = True
        user.save()
        return Response({"detail": "MFA successfully enabled"})
    else:
        return Response({"error": "Invalid verification code"}, status=400)
    

# This logic is for MFA Verification during login
@extend_schema(request=MFAVerifySerializer, responses={200: MFAVerifySerializer})
@api_view(['POST'])
def login(request):
    username = request.data.get("username")
    password = request.data.get("password")

    user = authenticate(username=username, password=password)
    if not user:
        return Response({"error": "Invalid credentials"}, status=401)

    if user.mfa_enabled:
        temp_token = get_random_string(32)
        cache.set(temp_token, user.id, timeout=300)  # valid 5 minutes
        return Response({
            "mfa_required": True,
            "temp_token": temp_token
        })

    login(request, user)
    return Response({"detail": "Login successful, session created"})

#So this logic will help in MFA verification by checking the code
@extend_schema(request=MFAVerifySerializer, responses={200: MFAVerifySerializer})
@api_view(['POST'])
def mfa_verify(request):
    temp_token = request.data.get("temp_token")
    code = request.data.get("code")

    user_id = cache.get(temp_token)
    if not user_id:
        return Response({"error": "Expired or invalid session"}, status=400)

    from django.contrib.auth import get_user_model
    User = get_user_model()
    user = User.objects.get(id=user_id)

    totp = pyotp.TOTP(user.get_mfa_secret())
    if not totp.verify(code):
        return Response({"error": "Invalid or expired code"}, status=401)

    # This logic says if Valid code ,finalize login
    cache.delete(temp_token)
    login(request, user)  #This sets the Django session cookie
    return Response({"detail": "MFA success, session created"})



# Employee Invitation Serializers
class EmployeeInvitationAcceptSerializer(serializers.Serializer):
    token = serializers.CharField(
        required=True,
        help_text="Invitation token from the email link"
    )
    password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=8,
        help_text="Password for the new account"
    )
    username = serializers.CharField(
        required=True,
        help_text="User_name"
    )
    
    
    def validate_token(self, value):
        try:
            invitation = EmployeeInvitation.objects.get(
                token=value,
                accepted=False,
                expires_at__gt=timezone.now()
            )
            return value
        except EmployeeInvitation.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired invitation token")

    def create(self, validated_data):
        token = validated_data['token']
        password = validated_data['password']
        first_name = validated_data['first_name']
        last_name = validated_data['last_name']
        
        # Get the invitation
        invitation = EmployeeInvitation.objects.get(
            token=token,
            accepted=False,
            expires_at__gt=timezone.now()
        )
        
        # Create user account
        user = User.objects.create_user(
            username=invitation.email,  # Use email as username
            email=invitation.email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            is_active=True
        )
        
        # Create employee profile
        employee_profile = Employee.objects.create(
            user=user,
            employer=invitation.employer
        )
        
        # Mark invitation as accepted
        invitation.accepted = True
        invitation.accepted_at = timezone.now()
        invitation.save()
        
        return user

#--- Serializer for creating employee user account ---
class EmployeeUserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'password_confirm']
    
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
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_active=True
        )
        return user


# --- Employee Invitation Views ---
@extend_schema(tags=['Employee Invitations'])
class InviteView(viewsets.ModelViewSet):
    """
    Employee Invitation Management
    
    Allows employers to:
    - Send email invitations to new employees
    - View pending invitations
    - Resend or cancel invitations
    """
    serializer_class = EmployeeInvitationCreateSerializer
    permission_classes = [permissions.IsAuthenticated]  # Allow any authenticated user with an organization

    def get_queryset(self):
        # Get invitations for the employer's organization
        employer = None
        
        # First, check if user has an Organization (for organization owners)
        try:
            organization = Organization.objects.filter(owner=self.request.user).first()
            if organization:
                # Get or create Employer from Organization
                employer, created = Employer.objects.get_or_create(
                    name=organization.organizationName,
                    defaults={'is_active': True}
                )
        except Exception:
            pass
        
        # If no organization, try to get employer from employee profile
        if not employer:
            try:
                employee_profile = Employee.objects.filter(user=self.request.user).first()
                if employee_profile:
                    employer = employee_profile.employer
            except Exception:
                pass
        
        # If still no employer, check if user is staff and get first employer
        if not employer and self.request.user.is_staff:
            employer = Employer.objects.first()
        
        if employer:
            return EmployeeInvitation.objects.filter(employer=employer).order_by('-created_at')
        
        return EmployeeInvitation.objects.none()

    @extend_schema(
        request=EmployeeInvitationCreateSerializer,
        responses={
            201: {
                "description": "Invitation sent successfully",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Invitation sent successfully",
                            "invitation": {
                                "id": 1,
                                "email": "newemployee@company.com",
                                "message": "Welcome to our team!",
                                "expires_at": "2025-11-06T19:13:03.648Z",
                                "created_at": "2025-10-30T19:13:03.648Z"
                            },
                            "invitation_link": "/auth/accept-invite/?token=abc123xyz"
                        }
                    }
                }
            },
            400: {"description": "Bad Request - Invalid data or user has no organization"}
        },
        description="""
        Send an invitation to a new employee.
        
        The system will:
        - Generate a unique invitation token
        - Send an email to the invited person
        - Set an expiration date for the invitation (defaults to 7 days)
        
        **Example Request:**
        ```json
        {
          "email": "newemployee@company.com",
          "message": "Welcome to our team!"
        }
        ```
        
        **Note:** The employer is automatically set from your authenticated user.
        """
    )
    def create(self, request, *args, **kwargs):
        """Send an invitation to a new employee"""
        # Get the employer for the current user
        employer = None
        
        # First, check if user has an Organization (for organization owners)
        try:
            organization = Organization.objects.filter(owner=request.user).first()
            if organization:
                # Get or create Employer from Organization
                employer, created = Employer.objects.get_or_create(
                    name=organization.organizationName,
                    defaults={'is_active': True}
                )
        except Exception as e:
            logger.warning(f"Error getting organization: {str(e)}")
        
        # If no organization, try to get employer from employee profile
        if not employer:
            try:
                employee_profile = Employee.objects.filter(user=request.user).first()
                if employee_profile:
                    employer = employee_profile.employer
            except Exception:
                pass
        
        # If still no employer, check if user is staff and get first employer
        if not employer and request.user.is_staff:
            employer = Employer.objects.first()
        
        if not employer:
            return Response(
                {
                    "error": "You must be associated with an organization to send invitations",
                    "detail": "Please create or join an organization first"
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = self.get_serializer(
            data=request.data,
            context={
                'employer': employer,
                'user': request.user
            }
        )
        serializer.is_valid(raise_exception=True)
        invitation = serializer.save()
        
        # Send invitation email
        try:
            invitation_url = f"{settings.FRONTEND_URL}/auth/accept-invite?token={invitation.token}" if hasattr(settings, 'FRONTEND_URL') else f"http://localhost:3000/auth/accept-invite?token={invitation.token}"
            
            subject = f"You're invited to join {employer.name} on Obeeoma"
            message = f"""
Hello,

You have been invited to join {employer.name} on the Obeeoma platform by {request.user.username}.

{invitation.message if invitation.message else ''}

To accept this invitation and create your account, please click the link below:

{invitation_url}

Your invitation token: {invitation.token}

This invitation will expire on {invitation.expires_at.strftime('%B %d, %Y at %I:%M %p')}.

If you have any questions, please contact your organization administrator.

Best regards,
The Obeeoma Team
"""
            
            # Try to send via Gmail API first, fallback to SMTP
            email_sent = False
            try:
                # Only try Gmail API if credentials are configured
                if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET:
                    email_sent = send_gmail_api_email(invitation.email, subject, message)
                    logger.info(f"Email sent via Gmail API to {invitation.email}")
            except Exception as gmail_error:
                logger.warning(f"Gmail API failed: {str(gmail_error)}")
            
            # Fallback to SMTP if Gmail API didn't work
            if not email_sent:
                try:
                    send_mail(
                        subject,
                        message,
                        settings.DEFAULT_FROM_EMAIL,
                        [invitation.email],
                        fail_silently=False,
                    )
                    email_sent = True
                    logger.info(f"Email sent via SMTP to {invitation.email}")
                except Exception as smtp_error:
                    logger.error(f"SMTP failed: {str(smtp_error)}")
            
            if not email_sent:
                logger.error(f"Failed to send invitation email to {invitation.email}")
                
        except Exception as e:
            logger.error(f"Error sending invitation email: {str(e)}")
            # Don't fail the request if email fails, just log it
        
        return Response({
            'message': 'Invitation sent successfully',
            'invitation': serializer.data,
            'invitation_link': f'/auth/accept-invite/?token={invitation.token}'
        }, status=status.HTTP_201_CREATED)


@extend_schema(tags=['Employee Invitations'])
class InvitationAcceptanceView(APIView):
    """
    Handle employee invitation acceptance and account creation
    """
    permission_classes = [AllowAny]  # Allow unauthenticated access for signup
    
    @extend_schema(
        request=EmployeeInvitationAcceptSerializer,
        responses={
            200: {
                "description": "Invitation validated successfully",
                "content": {
                    "application/json": {
                        "example": {
                            "valid": True,
                            "invitation": {
                                "email": "employee@company.com",
                                "employer": "Company Name",
                                "invited_by": "admin@company.com",
                                "expires_at": "2025-11-06T19:13:03.648Z"
                            }
                        }
                    }
                }
            },
            400: {"description": "Invalid or expired token"}
        }
    )
    def post(self, request):
        """
        Validate invitation token and return invitation details
        """
        serializer = EmployeeInvitationAcceptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        token = serializer.validated_data['token']
        invitation = EmployeeInvitation.objects.get(
            token=token,
            accepted=False,
            expires_at__gt=timezone.now()
        )
        
        return Response({
            'valid': True,
            'invitation': {
                'email': invitation.email,
                'employer': invitation.employer.name,
                'invited_by': invitation.invited_by.email if invitation.invited_by else 'Unknown',
                'expires_at': invitation.expires_at
            }
        })
    
    @extend_schema(
        request=EmployeeUserCreateSerializer,
        responses={
            201: {
                "description": "Account created successfully",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Account created successfully",
                            "user": {
                                "id": 1,
                                "email": "employee@company.com",
                                "first_name": "John",
                                "last_name": "Doe"
                            },
                            "employee_profile": {
                                "id": 1,
                                "employer": "Company Name"
                            }
                        }
                    }
                }
            },
            400: {"description": "Invalid data or token"}
        }
    )
    def put(self, request):
        """
        Create employee account using validated invitation
        """
        # First validate the token
        token_serializer = EmployeeInvitationAcceptSerializer(data=request.data)
        token_serializer.is_valid(raise_exception=True)
        
        token = token_serializer.validated_data['token']
        invitation = EmployeeInvitation.objects.get(
            token=token,
            accepted=False,
            expires_at__gt=timezone.now()
        )
        
        # Create user account
        user_data = {
            'email': invitation.email,
            'user_name': request.data.get('user_name'),
            'password': request.data.get('password'),
            'password_confirm': request.data.get('password_confirm'),
        }
        
        user_serializer = EmployeeUserCreateSerializer(data=user_data)
        user_serializer.is_valid(raise_exception=True)
        user = user_serializer.save()
        
        # Create employee profile
        employee_profile = Employee.objects.create(
            user=user,
            employer=invitation.employer
        )
        
        # Mark invitation as accepted
        invitation.accepted = True
        invitation.accepted_at = timezone.now()
        invitation.save()
        
        return Response({
            'message': 'Account created successfully',
            'user': {
                'id': user.id,
                'email': user.email,
                'user_name': user.user_name,
            },
            'employee_profile': {
                'id': employee_profile.id,
                'employer': invitation.employer.name
            }
        }, status=status.HTTP_201_CREATED)


@extend_schema(
    tags=['Employee Invitations'],
    request={'token': 'string'},
    responses={200: {'valid': 'boolean', 'invitation': 'object'}}
)
class InvitationVerifyView(APIView):
    """Verify an invitation token before signup"""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """
        Verify if an invitation token is valid.
        
        Query parameter: ?token=abc123xyz
        """
        token = request.query_params.get('token')
        
        if not token:
            return Response(
                {"error": "Token parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            invitation = EmployeeInvitation.objects.get(token=token, accepted=False)
            
            # Check if expired
            if invitation.expires_at < timezone.now():
                return Response(
                    {
                        "valid": False,
                        "error": "Invitation has expired",
                        "expired_at": invitation.expires_at
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response({
                "valid": True,
                "email": invitation.email,
                "organization": invitation.employer.name,
                "invited_by": invitation.invited_by.username if invitation.invited_by else "Administrator",
                "expires_at": invitation.expires_at,
                "message": invitation.message
            })
            
        except EmployeeInvitation.DoesNotExist:
            return Response(
                {
                    "valid": False,
                    "error": "Invalid or already used invitation token"
                },
                status=status.HTTP_400_BAD_REQUEST
            )


@extend_schema(
    tags=["Authentication"],
    request=EmployeeInvitationAcceptSerializer,
    responses={
        201: {
            "description": "Account created successfully",
            "content": {
                "application/json": {
                    "example": {
                        "message": "Account created successfully",
                        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "user": {
                            "id": 1,
                            "username": "newemployee",
                            "email": "newemployee@company.com",
                            "role": "employee"
                        }
                    }
                }
            }
        },
        400: {"description": "Invalid token, expired invitation, or validation error"}
    },
    description="""
    Accept an employee invitation and create a new account.
    
    The invited person should:
    1. Receive an email with an invitation token
    2. Use this endpoint to create their account with the token
    3. Provide a username and password
    
    **Example Request:**
    ```json
    {
      "token": "abc123xyz789",
      "username": "johndoe",
      "password": "SecurePassword123!"
    }
    ```
    
    Upon success, the user account is created and linked to the organization.
    """
)
class InvitationAcceptView(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]
    serializer_class = EmployeeInvitationAcceptSerializer

    def create(self, request):
        """Accept invitation and create employee account"""
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
        # Get user data
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "date_joined": user.date_joined,
            "is_active": user.is_active,
        }
        
        return Response({
            'message': 'Account created successfully',
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': user_data
        }, status=status.HTTP_201_CREATED)


# --- Employer Dashboard ---
@extend_schema(tags=['Employer Dashboard'])
class OverviewView(viewsets.ViewSet):
    permission_classes = [IsCompanyAdmin]

    def list(self, request):
        employee_count = Employee.objects.count()
        active_subscriptions = Subscription.objects.filter(is_active=True).count()
        recent = RecentActivity.objects.select_related("employer").order_by("-timestamp")[:10]
        recent_serialized = RecentActivitySerializer(recent, many=True).data
        return Response({
            "employee_count": employee_count,
            "active_subscriptions": active_subscriptions,
            "recent_activities": recent_serialized,
        })


@extend_schema(tags=['Employer Dashboard'])
class TrendsView(viewsets.ReadOnlyModelViewSet):
    queryset = HotlineActivity.objects.select_related("employer").order_by("-recorded_at")
    serializer_class = HotlineActivitySerializer
    permission_classes = [IsCompanyAdmin]


@extend_schema(tags=['Employer Dashboard'])
class EmployeeEngagementView(viewsets.ModelViewSet):
    queryset = EmployeeEngagement.objects.select_related("employer").order_by("-month")
    serializer_class = EmployeeEngagementSerializer
    permission_classes = [IsCompanyAdmin]


from drf_spectacular.utils import extend_schema, extend_schema_view

@extend_schema_view(
    list=extend_schema(
        operation_id="features_usage_list",
        tags=["Employer Dashboard"]
    ),
    by_category=extend_schema(
        operation_id="features_usage_by_category",
        tags=["Employer Dashboard"],
        description="Returns feature usage grouped by category."
    )
)
class FeaturesUsageView(viewsets.ModelViewSet):
    queryset = AIManagement.objects.select_related("employer").order_by("-created_at")
    serializer_class = AIManagementSerializer
    permission_classes = [IsCompanyAdmin]

    @action(detail=False, methods=['get'])
    def by_category(self, request):
        return Response({"message": "Feature flags grouped by category"})


@extend_schema(tags=['Employer Dashboard'])
class BillingView(viewsets.ModelViewSet):
    queryset = Subscription.objects.select_related("employer").all()
    serializer_class = SubscriptionSerializer
    permission_classes = [IsCompanyAdmin]

    @action(detail=False, methods=['get'])
    def summary(self, request):
        subscriptions = self.get_queryset()
        total_revenue = sum(float(s.amount) for s in subscriptions)
        return Response({
            "subscriptions": SubscriptionSerializer(subscriptions, many=True).data,
            "total_revenue": total_revenue
        })


@extend_schema(tags=['Employer Dashboard'])
class UsersView(viewsets.ModelViewSet):
    queryset = Employee.objects.select_related("employer").all()
    serializer_class = EmployeeSerializer
    permission_classes = [IsCompanyAdmin]


@extend_schema(tags=['Employer Dashboard'])
class ReportsView(viewsets.ReadOnlyModelViewSet):
    queryset = RecentActivity.objects.select_related("employer").order_by("-timestamp")
    serializer_class = RecentActivitySerializer
    permission_classes = [IsCompanyAdmin]

# For crisis insights about hotline activities and for which reasons employees are reaching out.
@extend_schema(tags=['Employer Dashboard'])
class CrisisInsightsView(viewsets.ReadOnlyModelViewSet):
    queryset = HotlineActivity.objects.select_related("employer").order_by("-recorded_at")
    serializer_class = HotlineActivitySerializer
    permission_classes = [IsCompanyAdmin]


def home(request):
    return JsonResponse({"status": "ok", "app": "obeeomaapp"})


@extend_schema(tags=['Authentication'])
class EmailConfigCheckView(APIView):
    """Debug endpoint to check email configuration"""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        import os
        db_config = settings.DATABASES['default']
        
        config = {
            "database": {
                "engine": db_config.get('ENGINE'),
                "name": str(db_config.get('NAME')),
                "host": db_config.get('HOST', 'Not set'),
                "user": db_config.get('USER', 'Not set'),
            },
            "environment_vars": {
                "DATABASE_URL": "Set" if os.getenv('DATABASE_URL') else "NOT SET",
                "PGHOST": "Set" if os.getenv('PGHOST') else "NOT SET",
            },
            "email": {
                "email_backend": settings.EMAIL_BACKEND,
                "email_host": settings.EMAIL_HOST,
                "email_port": settings.EMAIL_PORT,
                "email_use_tls": settings.EMAIL_USE_TLS,
                "email_host_user": settings.EMAIL_HOST_USER,
                "default_from_email": settings.DEFAULT_FROM_EMAIL,
                "has_email_password": bool(settings.EMAIL_HOST_PASSWORD),
            },
            "debug_mode": settings.DEBUG,
        }
        return Response(config)


# --- Employee App ---

@extend_schema(tags=['Employee - Profile'])
class EmployeeProfileView(viewsets.ModelViewSet):
    serializer_class = EmployeeProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return EmployeeProfile.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


@extend_schema(tags=['Employee - Profile'])
class AvatarProfileView(viewsets.ModelViewSet):
    serializer_class = AvatarProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return AvatarProfile.objects.filter(employee__user=self.request.user)


@extend_schema(tags=['Employee - Wellness'])
class WellnessHubView(viewsets.ModelViewSet):
    serializer_class = WellnessHubSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return WellnessHub.objects.filter(employee__user=self.request.user)

@extend_schema(tags=['Employee - Mood Tracking'])
class MoodTrackingView(viewsets.ModelViewSet):
    serializer_class = MoodTrackingSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['mood']
    search_fields = ['note']

    def get_queryset(self):
        return EmployeeProfile.objects.filter(user=self.request.user)

        return MoodTracking.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        employee = get_object_or_404(EmployeeProfile, user=self.request.user)
        serializer.save(user=self.request.user, employee=employee)



@extend_schema(tags=['Employee - Assessments'])
class AssessmentResultView(viewsets.ModelViewSet):
    serializer_class = AssessmentResultSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return AvatarProfile.objects.filter(employee__user=self.request.user)

    def perform_create(self, serializer):
        employee = get_object_or_404(EmployeeProfile, user=self.request.user)
        serializer.save(employee=employee)


@extend_schema(tags=['Resources'])
class SelfHelpResourceView(viewsets.ModelViewSet):
    queryset = SelfHelpResource.objects.all()
    serializer_class = SelfHelpResourceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return WellnessHub.objects.filter(employee__user=self.request.user)


@extend_schema(tags=['Resources'])
class EducationalResourceView(viewsets.ModelViewSet):
    queryset = EducationalResource.objects.all()
    serializer_class = EducationalResourceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return AssessmentResult.objects.filter(employee__user=self.request.user)

@extend_schema(tags=['Employee - Crisis Support'])
class CrisisTriggerView(viewsets.ModelViewSet):
    serializer_class = CrisisTriggerSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return CrisisTrigger.objects.filter(employee__user=self.request.user)



@extend_schema(tags=['Employee - Notifications'])
class NotificationView(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['is_read', 'notification_type']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        return Notification.objects.filter(employee__user=self.request.user)


@extend_schema(tags=['Employee - Engagement'])
class EngagementTrackerView(viewsets.ModelViewSet):
    serializer_class = EngagementTrackerSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return EngagementTracker.objects.filter(employee__user=self.request.user)


class FeedbackFilterSet(FilterSet):
    feedback_type = CharFilter(method='filter_feedback_type')

    def filter_feedback_type(self, queryset, name, value):
        return queryset.filter(feedback_type__icontains=value)

    class Meta:
        model = Feedback
        fields = ['rating']  # Only include actual model fields here


@extend_schema(tags=['Employee - Feedback'])
class FeedbackView(viewsets.ModelViewSet):
    serializer_class = FeedbackSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['rating', 'feedback_type']
    ordering_fields = ['created_at', 'rating']
    ordering = ['-created_at']

    def get_queryset(self):
        return Feedback.objects.filter(employee__user=self.request.user)

    @action(detail=False, methods=['get'])
    def average_rating(self, request):
        from django.db.models import Avg
        avg = self.get_queryset().aggregate(average=Avg('rating'))
        return Response({
            'average_rating': round(avg['average'], 2) if avg['average'] else 0,
            'total_feedback': self.get_queryset().count()
        })




@extend_schema(tags=['Employee - AI Chat'])
class ChatSessionView(viewsets.ModelViewSet):
    serializer_class = ChatSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['is_active']
    ordering_fields = ['created_at', 'last_message_at']
    ordering = ['-last_message_at']

    def get_queryset(self):
        return ChatSession.objects.filter(employee__user=self.request.user)

    @action(detail=False, methods=['get'])
    def active(self, request):
        active_sessions = self.get_queryset().filter(is_active=True)
        serializer = self.get_serializer(active_sessions, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def end_session(self, request, pk=None):
        session = self.get_object()
        session.is_active = False
        session.save()
        return Response({
            'message': 'Chat session ended successfully',
            'session': self.get_serializer(session).data
        })


@extend_schema(tags=['Employee - AI Chat'])
class ChatMessageView(viewsets.ModelViewSet):
    serializer_class = ChatMessageSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['created_at']
    ordering = ['created_at']

    def get_queryset(self):
        return ChatMessage.objects.filter(session__employee__user=self.request.user)

    def perform_create(self, serializer):
        session = get_object_or_404(ChatSession, id=self.kwargs.get("session_id"), employee__user=self.request.user)
        serializer.save(session=session)


@extend_schema(tags=['Employee - Recommendations'])
class RecommendationLogView(viewsets.ModelViewSet):
    serializer_class = RecommendationLogSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return RecommendationLog.objects.filter(employee__user=self.request.user)

    def perform_create(self, serializer):
        employee = get_object_or_404(EmployeeProfile, user=self.request.user)
        serializer.save(employee=employee)


@extend_schema(tags=['Employee - Assessments'])
class MentalHealthAssessmentViewSet(viewsets.ModelViewSet):
    """ViewSet for mental health assessments"""
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return MentalHealthAssessment.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        if self.action == 'list':
            return MentalHealthAssessmentListSerializer
        return MentalHealthAssessmentSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=False, methods=['get'], url_path='questionnaires')
    def get_questionnaires(self, request):
        """Get assessment questionnaires with all questions"""
        questionnaires = {
            "gad7": {
                "name": "GAD-7 (Generalized Anxiety Disorder)",
                "description": "This questionnaire measures anxiety symptoms over the past 2 weeks.",
                "instructions": "Over the last 2 weeks, how often have you been bothered by the following problems?",
                "response_options": [
                    {"value": 0, "label": "Not at all"},
                    {"value": 1, "label": "Several days"},
                    {"value": 2, "label": "More than half the days"},
                    {"value": 3, "label": "Nearly every day"}
                ],
                "questions": [
                    {"id": 1, "text": "Feeling nervous, anxious, or on edge"},
                    {"id": 2, "text": "Not being able to stop or control worrying"},
                    {"id": 3, "text": "Worrying too much about different things"},
                    {"id": 4, "text": "Trouble relaxing"},
                    {"id": 5, "text": "Being so restless that it's hard to sit still"},
                    {"id": 6, "text": "Becoming easily annoyed or irritable"},
                    {"id": 7, "text": "Feeling afraid as if something awful might happen"}
                ],
                "scoring": {
                    "minimal": {"range": "0-4", "description": "Minimal anxiety"},
                    "mild": {"range": "5-9", "description": "Mild anxiety"},
                    "moderate": {"range": "10-14", "description": "Moderate anxiety"},
                    "severe": {"range": "15-21", "description": "Severe anxiety"}
                }
            },
            "phq9": {
                "name": "PHQ-9 (Patient Health Questionnaire)",
                "description": "This questionnaire measures depression symptoms over the past 2 weeks.",
                "instructions": "Over the last 2 weeks, how often have you been bothered by any of the following problems?",
                "response_options": [
                    {"value": 0, "label": "Not at all"},
                    {"value": 1, "label": "Several days"},
                    {"value": 2, "label": "More than half the days"},
                    {"value": 3, "label": "Nearly every day"}
                ],
                "questions": [
                    {"id": 1, "text": "Little interest or pleasure in doing things"},
                    {"id": 2, "text": "Feeling down, depressed, or hopeless"},
                    {"id": 3, "text": "Trouble falling or staying asleep, or sleeping too much"},
                    {"id": 4, "text": "Feeling tired or having little energy"},
                    {"id": 5, "text": "Poor appetite or overeating"},
                    {"id": 6, "text": "Feeling bad about yourself - or that you are a failure or have let yourself or your family down"},
                    {"id": 7, "text": "Trouble concentrating on things, such as reading the newspaper or watching television"},
                    {"id": 8, "text": "Moving or speaking so slowly that other people could have noticed. Or the opposite - being so fidgety or restless that you have been moving around a lot more than usual"},
                    {"id": 9, "text": "Thoughts that you would be better off dead, or of hurting yourself in some way"}
                ],
                "scoring": {
                    "minimal": {"range": "0-4", "description": "Minimal depression"},
                    "mild": {"range": "5-9", "description": "Mild depression"},
                    "moderate": {"range": "10-14", "description": "Moderate depression"},
                    "moderately_severe": {"range": "15-19", "description": "Moderately severe depression"},
                    "severe": {"range": "20-27", "description": "Severe depression"}
                },
                "crisis_note": "If you answered question 9 with anything other than 'Not at all', please seek immediate help. Contact a mental health professional or call a crisis hotline."
            },
            "submission_format": {
                "description": "How to submit your responses",
                "example_gad7_only": {
                    "assessment_type": "GAD-7",
                    "gad7_responses": [0, 1, 2, 1, 0, 2, 1]
                },
                "example_phq9_only": {
                    "assessment_type": "PHQ-9",
                    "phq9_responses": [1, 2, 1, 0, 1, 2, 1, 0, 1]
                },
                "example_both": {
                    "assessment_type": "BOTH",
                    "gad7_responses": [0, 1, 2, 1, 0, 2, 1],
                    "phq9_responses": [1, 2, 1, 0, 1, 2, 1, 0, 1]
                },
                "submit_endpoint": "/api/v1/mental-health/assessments/submit-assessment/"
            }
        }
        
        return Response(questionnaires)

    @action(detail=False, methods=['post'], url_path='submit-assessment')
    def submit_assessment(self, request):
        """Submit a new assessment with responses"""
        serializer = AssessmentResponseSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data
            assessment_type = data['assessment_type']
            gad7_responses = data.get('gad7_responses', [])
            phq9_responses = data.get('phq9_responses', [])

            # Create assessment instance
            assessment_data = {
                'assessment_type': assessment_type,
                'gad7_scores': gad7_responses,
                'phq9_scores': phq9_responses,
            }
            
            assessment_serializer = MentalHealthAssessmentSerializer(data=assessment_data)
            if assessment_serializer.is_valid():
                assessment = assessment_serializer.save(user=request.user)
                
                return Response({
                    'message': 'Assessment submitted successfully',
                    'assessment': MentalHealthAssessmentSerializer(assessment).data
                }, status=status.HTTP_201_CREATED)
            else:
                return Response(assessment_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'], url_path='my-results')
    def my_results(self, request):
        """Get user's assessment results with summary"""
        assessments = self.get_queryset()
        
        if not assessments.exists():
            return Response({
                'message': 'No assessments found',
                'assessments': [],
                'summary': None
            })

        # Get latest assessment
        latest = assessments.first()
        
        # Calculate summary statistics
        all_assessments = list(assessments.values('gad7_total', 'phq9_total', 'assessment_date'))
        
        summary = {
            'total_assessments': len(all_assessments),
            'latest_assessment_date': latest.assessment_date,
            'latest_gad7_score': latest.gad7_total,
            'latest_phq9_score': latest.phq9_total,
            'latest_gad7_severity': latest.gad7_severity,
            'latest_phq9_severity': latest.phq9_severity,
            'average_gad7_score': sum(a['gad7_total'] for a in all_assessments if a['gad7_total'] > 0) / max(1, len([a for a in all_assessments if a['gad7_total'] > 0])),
            'average_phq9_score': sum(a['phq9_total'] for a in all_assessments if a['phq9_total'] > 0) / max(1, len([a for a in all_assessments if a['phq9_total'] > 0])),
        }

        return Response({
            'assessments': MentalHealthAssessmentListSerializer(assessments, many=True).data,
            'summary': summary
        })

    @action(detail=True, methods=['get'], url_path='detailed-results')
    def detailed_results(self, request, pk=None):
        """Get detailed results for a specific assessment"""
        assessment = self.get_object()
        
        detailed_data = {
            'assessment': MentalHealthAssessmentSerializer(assessment).data,
            'interpretation': {
                'gad7': {
                    'score': assessment.gad7_total,
                    'severity': assessment.gad7_severity,
                    'recommendation': self._get_gad7_recommendation(assessment.gad7_total)
                },
                'phq9': {
                    'score': assessment.phq9_total,
                    'severity': assessment.phq9_severity,
                    'recommendation': self._get_phq9_recommendation(assessment.phq9_total)
                }
            }
        }
        
        return Response(detailed_data)

    def _get_gad7_recommendation(self, score):
        """Get recommendation based on GAD-7 score"""
        if score <= 4:
            return "Your anxiety levels are minimal. Continue with current self-care practices."
        elif score <= 9:
            return "Mild anxiety detected. Consider stress management techniques and regular check-ins."
        elif score <= 14:
            return "Moderate anxiety levels. Consider speaking with a healthcare provider or mental health professional."
        else:
            return "Severe anxiety levels. Please consider reaching out to a mental health professional for support."

    def _get_phq9_recommendation(self, score):
        """Get recommendation based on PHQ-9 score"""
        if score <= 4:
            return "Your mood appears stable. Continue with current self-care practices."
        elif score <= 9:
            return "Mild depression symptoms detected. Consider mood tracking and self-care activities."
        elif score <= 14:
            return "Moderate depression symptoms. Consider speaking with a healthcare provider."
        elif score <= 19:
            return "Moderately severe depression symptoms. Please consider reaching out to a mental health professional."
        else:
            return "Severe depression symptoms detected. Please seek immediate support from a mental health professional."


# --- Employee-specific: Badges and Engagement Streaks ---
@extend_schema(tags=['Employee - Engagement'])
class MyBadgesView(viewsets.ReadOnlyModelViewSet):
    serializer_class = UserBadgeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return UserBadge.objects.filter(user=self.request.user)


@extend_schema(tags=['Employee - Engagement'])
class MyStreaksView(viewsets.ReadOnlyModelViewSet):
    serializer_class = EngagementStreakSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return EngagementStreak.objects.filter(user=self.request.user).order_by('-last_active_date')


# --- Employer APIs ---
@extend_schema(tags=['Employer - Organization'])
class EmployerViewSet(viewsets.ModelViewSet):
    queryset = Employer.objects.all()
    serializer_class = EmployerSerializer
    
    def get_permissions(self):
        """
        Only employers can create organizations (not system admins).
        System admins can only view, update, and delete.
        """
        if self.action == 'create':
            # Block creation through this endpoint - use EmployerRegistrationView instead
            return [permissions.IsAuthenticated()]
        elif self.action in ['list', 'retrieve']:
            return [permissions.IsAuthenticated()]
        else:
            # Update, delete require admin
            return [IsCompanyAdmin()]
    
    def create(self, request, *args, **kwargs):
        """
        Block direct creation - employers should use /auth/register-organization/ endpoint
        """
        return Response(
            {
                "error": "Please use /auth/register-organization/ endpoint to create an organization",
                "detail": "Direct organization creation is not allowed. Use the employer registration endpoint."
            },
            status=status.HTTP_403_FORBIDDEN
        )
        
    def get_queryset(self):
        """
        Employers can only see their own organization.
        Admins can see all organizations.
        """
        if self.request.user.is_staff:
            return Employer.objects.all()
        # Return organizations where user is linked
        return Employer.objects.filter(
            employees__user=self.request.user
        ).distinct()
    
    def perform_create(self, serializer):
        """
        When an employer creates an organization, link them to it.
        """
        employer = serializer.save()
        # Create an employee profile linking the user to this organization
        if not hasattr(self.request.user, 'employee_profile'):
            Employee.objects.create(
                employer=employer,
                user=self.request.user,
                first_name=self.request.user.first_name or self.request.user.username,
                last_name=self.request.user.last_name or '',
                email=self.request.user.email,
                status='active'
            )

    @action(detail=True, methods=['get'])
    def overview(self, request, pk=None):
        employer = self.get_object()
        data = {
            "employee_count": Employee.objects.filter(employer=employer).count(),
            "active_subscriptions": Subscription.objects.filter(employer=employer, is_active=True).count(),
            "engagement_entries": EmployeeEngagement.objects.filter(employer=employer).count(),
            "latest_hotline_activity": HotlineActivitySerializer(
                HotlineActivity.objects.filter(employer=employer).order_by('-recorded_at').first()
            ).data if HotlineActivity.objects.filter(employer=employer).exists() else None,
            "recent_activities": RecentActivitySerializer(
                RecentActivity.objects.filter(employer=employer).order_by('-timestamp')[:10], many=True
            ).data,
        }
        return Response(data)

    @action(detail=True, methods=['get'])
    def employees(self, request, pk=None):
        employer = self.get_object()
        qs = Employee.objects.filter(employer=employer).order_by('-joined_date')
        return Response(EmployeeSerializer(qs, many=True).data)

    @action(detail=True, methods=['get'])
    def subscriptions(self, request, pk=None):
        employer = self.get_object()
        qs = Subscription.objects.filter(employer=employer).order_by('-start_date')
        return Response(SubscriptionSerializer(qs, many=True).data)

    @action(detail=True, methods=['get'])
    def features(self, request, pk=None):
        employer = self.get_object()
        qs = AIManagement.objects.filter(employer=employer).order_by('-created_at')
        return Response(AIManagementSerializer(qs, many=True).data)

    @action(detail=True, methods=['get'])
    def engagements(self, request, pk=None):
        employer = self.get_object()
        qs = EmployeeEngagement.objects.filter(employer=employer).order_by('-month')
        return Response(EmployeeEngagementSerializer(qs, many=True).data)

    @action(detail=True, methods=['get'])
    def activities(self, request, pk=None):
        employer = self.get_object()
        qs = RecentActivity.objects.filter(employer=employer).order_by('-timestamp')
        return Response(RecentActivitySerializer(qs, many=True).data)

    @action(detail=True, methods=['post'], permission_classes=[IsCompanyAdmin])
    def invite(self, request, pk=None):
        employer = self.get_object()
        serializer = EmployeeInvitationCreateSerializer(data=request.data, context={'employer': employer, 'user': request.user})
        serializer.is_valid(raise_exception=True)
        invite = serializer.save()
        return Response({'message': 'Invitation created', 'token': invite.token}, status=status.HTTP_201_CREATED)


@extend_schema(tags=['Employee - Progress'])
class ProgressViewSet(viewsets.ModelViewSet):
    queryset = Progress.objects.all()
    serializer_class = ProgressSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAdminUser])
    def analytics(self, request):
        data = {
            "average_mood": Progress.objects.aggregate(Avg('mood_score'))['mood_score__avg'],
            "total_users": User.objects.count(),
            "progress_entries": Progress.objects.count(),
        }
        return Response(data)
# New Dashboard Views
@extend_schema(tags=['Employer Dashboard'])
class OrganizationOverviewView(viewsets.ViewSet):
    """Organization overview dashboard data"""
    permission_classes = [IsCompanyAdmin]
    
    def list(self, request):
        # Get total employees
        total_employees = Employee.objects.count()
        
        # Get total tests
        total_tests = WellnessTest.objects.count()
        
        # Get average score
        avg_score = WellnessTest.objects.aggregate(avg_score=Avg('score'))['avg_score'] or 0
        
        # Get at-risk departments
        at_risk_departments = Department.objects.filter(at_risk=True).count()
        
        # Get recent activities
        recent_activities = OrganizationActivity.objects.select_related('employer', 'department', 'employee').order_by('-created_at')[:10]
        
        data = {
            'total_employees': total_employees,
            'total_tests': total_tests,
            'average_score': round(avg_score, 2),
            'at_risk_departments': at_risk_departments,
            'recent_activities': OrganizationActivitySerializer(recent_activities, many=True).data
        }
        
        return Response(data)


@extend_schema(tags=['Employer Dashboard'])
class EmployeeManagementView(viewsets.ModelViewSet):
    """Employee management with search and filtering"""
    queryset = Employee.objects.select_related('employer', 'department').all()
    serializer_class = EmployeeManagementSerializer
    permission_classes = [IsCompanyAdmin]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['first_name', 'last_name', 'email', 'department__name']
    ordering_fields = ['first_name', 'email', 'joined_date', 'status']
    ordering = ['-joined_date']
    
    def get_queryset(self):
        queryset = super().get_queryset()
        department = self.request.query_params.get('department', None)
        status = self.request.query_params.get('status', None)
        
        if department:
            queryset = queryset.filter(department__name__icontains=department)
        if status:
            queryset = queryset.filter(status=status)
            
        return queryset
    
    def perform_create(self, serializer):
        """Create employee with proper employer assignment"""
        serializer.save()


@extend_schema(tags=['Employer Dashboard'])
class DepartmentManagementView(viewsets.ModelViewSet):
    """Department management"""
    queryset = Department.objects.select_related('employer').all()
    serializer_class = DepartmentSerializer
    permission_classes = [IsCompanyAdmin]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']
    
    def perform_create(self, serializer):
        """Create department with proper employer assignment"""
        # Get employer from request user or use first employer
        employer = Employer.objects.first()
        if hasattr(self.request.user, 'employer_profile'):
            employer = self.request.user.employer_profile.employer
        serializer.save(employer=employer)


@extend_schema(tags=['Employer Dashboard'])
class SubscriptionManagementView(viewsets.ModelViewSet):
    """Subscription management"""
    queryset = Subscription.objects.select_related('employer', 'plan_details', 'payment_method').all()
    serializer_class = SubscriptionManagementSerializer
    permission_classes = [IsCompanyAdmin]
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['start_date', 'amount']
    ordering = ['-start_date']
    
    @action(detail=False, methods=['get'])
    def current_subscription(self, request):
        """Get current active subscription"""
        subscription = self.get_queryset().filter(is_active=True).first()
        if subscription:
            return Response(SubscriptionManagementSerializer(subscription).data)
        return Response({'message': 'No active subscription found'}, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=False, methods=['get'])
    def available_plans(self, request):
        """Get available subscription plans"""
        plans = SubscriptionPlan.objects.filter(is_active=True)
        return Response(SubscriptionPlanSerializer(plans, many=True).data)
    
    @action(detail=False, methods=['get'])
    def billing_history(self, request):
        """Get billing history"""
        billing_history = BillingHistory.objects.select_related('employer').order_by('-billing_date')[:10]
        return Response(BillingHistorySerializer(billing_history, many=True).data)


@extend_schema(tags=['Employer Dashboard'])
class WellnessReportsView(viewsets.ViewSet):
    """Wellness reports and analytics"""
    permission_classes = [IsCompanyAdmin]
    
    def list(self, request):
        # Get common issues count
        common_issues = CommonIssue.objects.count()
        
        # Get resource engagement count
        resource_engagement = ResourceEngagement.objects.filter(completed=True).count()
        
        # Get average wellbeing trend
        avg_wellbeing = WellnessTest.objects.aggregate(avg_score=Avg('score'))['avg_score'] or 0
        
        # Get at-risk count
        at_risk = Department.objects.filter(at_risk=True).count()
        
        # Get chat engagement data
        chat_engagement = ChatEngagement.objects.all()[:5]
        
        # Get department contributions
        department_contributions = DepartmentContribution.objects.select_related('department').all()[:4]
        
        # Get recent activities
        recent_activities = OrganizationActivity.objects.select_related('employer', 'department', 'employee').order_by('-created_at')[:3]
        
        data = {
            'common_issues': common_issues,
            'resource_engagement': resource_engagement,
            'average_wellbeing_trend': round(avg_wellbeing, 2),
            'at_risk': at_risk,
            'chat_engagement': ChatEngagementSerializer(chat_engagement, many=True).data,
            'department_contributions': DepartmentContributionSerializer(department_contributions, many=True).data,
            'recent_activities': OrganizationActivitySerializer(recent_activities, many=True).data
        }
        
        return Response(data)


@extend_schema(tags=['Employer Dashboard'])
class OrganizationSettingsView(viewsets.ModelViewSet):
    """Organization settings management"""
    queryset = OrganizationSettings.objects.select_related('employer').all()
    serializer_class = OrganizationSettingsSerializer
    permission_classes = [IsCompanyAdmin]
    
    def get_queryset(self):
        return OrganizationSettings.objects.filter(employer__user=self.request.user)
    
    def perform_create(self, serializer):
        # Get or create employer for the current user
        employer, created = Employer.objects.get_or_create(
            name=f"{self.request.user.username}'s Organization"
        )
        serializer.save(employer=employer)


@extend_schema(tags=['Employer Dashboard'])
class TestsByTypeView(viewsets.ViewSet):
    """Tests by type analytics"""
    permission_classes = [IsCompanyAdmin]
    
    def list(self, request):
        tests_by_type = WellnessTest.objects.values('test_type').annotate(
            count=Count('id')
        ).order_by('-count')
        
        return Response(list(tests_by_type))


@extend_schema(tags=['Employer Dashboard'])
class TestsByDepartmentView(viewsets.ViewSet):
    """Tests by department analytics"""
    permission_classes = [IsCompanyAdmin]
    
    def list(self, request):
        
        tests_by_department = WellnessTest.objects.values(
            'department__name'
        ).annotate(
            count=Count('id')
        ).order_by('-count')
        
        return Response(list(tests_by_department))


# System Admin Views
@extend_schema(tags=['System Admin'])
class SystemAdminOverviewView(viewsets.ViewSet):
    """System Admin dashboard overview"""
    permission_classes = [IsCompanyAdmin]
    serializer_class = SystemAdminOverviewSerializer
    
    def list(self, request=None):
        from datetime import datetime, timedelta
        from django.db.models import Count
        
        # Calculate real-time metrics from database
        total_organizations = Employer.objects.count()
        total_clients = Employee.objects.count()
        
        # Calculate monthly revenue from active subscriptions
        monthly_revenue = Subscription.objects.filter(is_active=True).aggregate(
            total=Sum('amount')
        )['total'] or 0.00
        
        # Get hotline calls today
        today = timezone.now().date()
        hotline_calls_today = HotlineCall.objects.filter(call_date__date=today).count()
        
        # Get organizations this month
        first_day_of_month = datetime.now().replace(day=1).date()
        organizations_this_month = Employer.objects.filter(joined_date__gte=first_day_of_month).count()
        
        # Get clients this month
        clients_this_month = Employee.objects.filter(joined_date__gte=first_day_of_month).count()
        
        # Calculate revenue growth (compare to last month)
        last_month = (datetime.now().replace(day=1) - timedelta(days=1)).replace(day=1)
        last_month_revenue = BillingHistory.objects.filter(
            billing_date__year=last_month.year,
            billing_date__month=last_month.month,
            status='paid'
        ).aggregate(total=Sum('amount'))['total'] or 1
        
        current_month_revenue = BillingHistory.objects.filter(
            billing_date__year=datetime.now().year,
            billing_date__month=datetime.now().month,
            status='paid'
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        revenue_growth_percentage = ((current_month_revenue - last_month_revenue) / last_month_revenue * 100) if last_month_revenue > 0 else 0
        
        # Calculate hotline growth
        yesterday = today - timedelta(days=1)
        yesterday_calls = HotlineCall.objects.filter(call_date__date=yesterday).count()
        hotline_growth_percentage = ((hotline_calls_today - yesterday_calls) / yesterday_calls * 100) if yesterday_calls > 0 else 0
        
        # Get platform usage data
        platform_usage = PlatformUsage.objects.all().order_by('week_number')[:6]
        
        # Get subscription revenue data
        subscription_revenue = SubscriptionRevenue.objects.all().order_by('year', 'month')[:9]
        
        # Get recent system activities
        recent_activities = SystemActivity.objects.select_related('organization').order_by('-created_at')[:5]
        
        data = {
            'total_organizations': total_organizations,
            'total_clients': total_clients,
            'monthly_revenue': float(monthly_revenue),
            'hotline_calls_today': hotline_calls_today,
            'organizations_this_month': organizations_this_month,
            'clients_this_month': clients_this_month,
            'revenue_growth_percentage': round(float(revenue_growth_percentage), 2),
            'hotline_growth_percentage': round(float(hotline_growth_percentage), 2),
            'platform_usage': PlatformUsageSerializer(platform_usage, many=True).data,
            'subscription_revenue': SubscriptionRevenueSerializer(subscription_revenue, many=True).data,
            'recent_activities': SystemActivitySerializer(recent_activities, many=True).data
        }

        return Response(data)


@extend_schema(tags=['System Admin'])
class OrganizationsManagementView(viewsets.ModelViewSet):
    """Organizations management for system admin"""
    queryset = Employer.objects.all()
    serializer_class = OrganizationsManagementSerializer
    permission_classes = [IsCompanyAdmin]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter, DjangoFilterBackend]
    search_fields = ['name']
    ordering_fields = ['name', 'joined_date']
    ordering = ['-joined_date']
    filterset_fields = ['is_active', 'name']
    
    def retrieve(self, request, *args, **kwargs):
        """Get detailed information about a specific organization"""
        organization = self.get_object()
        
        # Get comprehensive organization data
        data = {
            "id": organization.id,
            "name": organization.name,
            "is_active": organization.is_active,
            "joined_date": organization.joined_date,
            
            # Employee statistics
            "total_employees": organization.employees.count(),
            "active_employees": organization.employees.filter(status='active').count(),
            "inactive_employees": organization.employees.filter(status='inactive').count(),
            
            # Department information
            "total_departments": organization.departments.count(),
            "at_risk_departments": organization.departments.filter(at_risk=True).count(),
            "departments": DepartmentSerializer(organization.departments.all(), many=True).data,
            
            # Subscription information
            "active_subscriptions": organization.subscriptions.filter(is_active=True).count(),
            "current_subscription": SubscriptionSerializer(
                organization.subscriptions.filter(is_active=True).first()
            ).data if organization.subscriptions.filter(is_active=True).exists() else None,
            
            # Activity metrics
            "total_assessments": Assessment.objects.filter(employee__employer=organization).count(),
            "recent_activities": RecentActivitySerializer(
                organization.activities.order_by('-timestamp')[:10], many=True
            ).data,
            
            # Engagement metrics
            "engagement_rate": organization.engagements.order_by('-month').first().engagement_rate if organization.engagements.exists() else 0,
            
            # Hotline activity
            "hotline_calls": organization.hotline_activities.count(),
            "latest_hotline_activity": HotlineActivitySerializer(
                organization.hotline_activities.order_by('-recorded_at').first()
            ).data if organization.hotline_activities.exists() else None,
            
            # Billing information
            "total_revenue": organization.billing_history.filter(status='paid').aggregate(
                total=Sum('amount')
            )['total'] or 0,
            "pending_invoices": organization.billing_history.filter(status='pending').count(),
        }
        
        return Response(data)
    
    @action(detail=False, methods=['get'], url_path='search-by-name')
    def search_by_name(self, request):
        """Search organizations by name and return detailed results"""
        name = request.query_params.get('name', '')
        
        if not name:
            return Response(
                {"error": "Please provide a 'name' query parameter"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Search for organizations matching the name
        organizations = Employer.objects.filter(name__icontains=name)
        
        if not organizations.exists():
            return Response(
                {"message": f"No organizations found matching '{name}'"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Return detailed info for each match
        results = []
        for org in organizations:
            results.append({
                "id": org.id,
                "name": org.name,
                "is_active": org.is_active,
                "joined_date": org.joined_date,
                "total_employees": org.employees.count(),
                "active_employees": org.employees.filter(status='active').count(),
                "total_departments": org.departments.count(),
                "current_plan": org.subscriptions.filter(is_active=True).first().plan if org.subscriptions.filter(is_active=True).exists() else "No active plan",
                "detail_url": f"/admin/organizations/{org.id}/"
            })
        
        return Response({
            "count": len(results),
            "results": results
        })
    
    @action(detail=False, methods=['get'])
    def growth_chart(self, request):
        """Get organization growth chart data"""
        from django.db.models import Count
        from datetime import datetime, timedelta
        
        # Get last 9 months of data
        months = []
        for i in range(9):
            date = datetime.now() - timedelta(days=30*i)
            months.append(date.strftime('%b'))
        
        # Get organization counts by month
        growth_data = []
        for i in range(9):
            date = datetime.now() - timedelta(days=30*i)
            count = Employer.objects.filter(joined_date__lte=date).count()
            growth_data.append(count)
        
        return Response({
            'months': list(reversed(months)),
            'counts': list(reversed(growth_data))
        })
    
    @action(detail=False, methods=['get'])
    def client_distribution(self, request):
        """Get client distribution by organization"""
        from django.db.models import Count
        
        distribution = Employer.objects.annotate(
            client_count=Count('employees')
        ).values('name', 'client_count').order_by('-client_count')[:6]
        
        return Response(list(distribution))


@extend_schema(tags=['System Admin'])
class HotlineActivityView(viewsets.ViewSet):
    """Hotline activity management for system admin"""
    permission_classes = [IsCompanyAdmin]
    serializer_class = HotlineActivitySerializer
    
    def list(self, request):
        from django.db.models import Count
        from datetime import datetime, timedelta
        
        # Get today's calls
        today_calls = HotlineCall.objects.filter(call_date__date=timezone.now().date()).count()
        
        # Get average duration
        avg_duration = HotlineCall.objects.aggregate(
            avg_duration=Avg('duration_minutes')
        )['avg_duration'] or 0
        
        # Get active operators count (unique operators who handled calls today)
        active_operators = HotlineCall.objects.filter(
            call_date__date=timezone.now().date()
        ).values('operator_name').distinct().count()
        
        # Get hourly volume data for today (real data)
        hourly_volume = []
        for hour in range(24):
            hour_start = timezone.now().replace(hour=hour, minute=0, second=0, microsecond=0)
            hour_end = hour_start + timedelta(hours=1)
            count = HotlineCall.objects.filter(
                call_date__gte=hour_start,
                call_date__lt=hour_end
            ).count()
            hourly_volume.append(count)
        
        # Get call reasons distribution
        call_reasons = HotlineCall.objects.values('reason').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Get recent calls
        recent_calls = HotlineCall.objects.select_related('organization').order_by('-call_date')[:10]
        
        # Get critical cases
        critical_cases = HotlineCall.objects.filter(
            urgency='critical'
        ).select_related('organization').order_by('-call_date')[:5]
        
        # Get operator performance (real data from today)
        operator_performance = []
        operators = HotlineCall.objects.filter(
            call_date__date=timezone.now().date()
        ).values('operator_name').distinct()
        
        for op in operators:
            operator_name = op['operator_name']
            calls = HotlineCall.objects.filter(
                operator_name=operator_name,
                call_date__date=timezone.now().date()
            )
            total_calls = calls.count()
            resolved_calls = calls.filter(status='resolved').count()
            resolution_rate = (resolved_calls / total_calls * 100) if total_calls > 0 else 0
            
            operator_performance.append({
                'name': operator_name,
                'calls': total_calls,
                'resolution_rate': round(resolution_rate, 0)
            })
        
        # Sort by calls descending
        operator_performance = sorted(operator_performance, key=lambda x: x['calls'], reverse=True)[:10]
        
        data = {
            'today_calls': today_calls,
            'average_duration': f"{int(avg_duration//60):02d}:{int(avg_duration%60):02d}",
            'active_operators': active_operators,
            'hourly_volume': hourly_volume,
            'call_reasons': list(call_reasons),
            'recent_calls': HotlineCallSerializer(recent_calls, many=True).data,
            'critical_cases': HotlineCallSerializer(critical_cases, many=True).data,
            'operator_performance': operator_performance
        }
        
        return Response(data)


@extend_schema(tags=['System Admin'])
class AIManagementView(viewsets.ViewSet):
    """AI Management dashboard for system admin"""
    permission_classes = [IsCompanyAdmin]
    serializer_class = AIManagementSerializer
    
    def list(self, request):
        # Get total recommendations
        try:
            total_recommendations = AIResource.objects.aggregate(
                total=Sum('recommended_count')
            )['total'] or 0
        except Exception:
            total_recommendations = 0
        
        # Get average engagement rate
        try:
            avg_engagement = AIResource.objects.aggregate(
                avg_rate=Avg('engagement_rate')
            )['avg_rate'] or 0
        except Exception:
            avg_engagement = 0
        
        # Get AI accuracy score
        try:
            ai_accuracy = AIResource.objects.aggregate(
                avg_accuracy=Avg('effectiveness_score')
            )['avg_accuracy'] or 0
        except Exception:
            ai_accuracy = 0
        
        # Get effectiveness by resource type
        try:
            effectiveness_by_type = AIResource.objects.values('resource_type').annotate(
                avg_effectiveness=Avg('effectiveness_score')
            ).order_by('-avg_effectiveness')
        except Exception:
            effectiveness_by_type = []
        
        # Get weekly recommendations (real data from last 6 weeks)
        from datetime import datetime, timedelta
        weekly_recommendations = []
        for i in range(6):
            week_start = timezone.now() - timedelta(weeks=i+1)
            week_end = timezone.now() - timedelta(weeks=i)
            week_count = RecommendationLog.objects.filter(
                recommended_on__gte=week_start,
                recommended_on__lt=week_end
            ).count()
            weekly_recommendations.insert(0, week_count)
        
        # Get resources
        resources = AIResource.objects.filter(is_active=True).order_by('-effectiveness_score')[:10]
        
        # Get top anxiety triggers from crisis triggers
        from django.db.models import Count
        top_anxiety_triggers = []
        crisis_triggers = CrisisTrigger.objects.values('detected_phrase').annotate(
            count=Count('id')
        ).order_by('-count')[:5]
        
        total_triggers = CrisisTrigger.objects.count()
        for trigger in crisis_triggers:
            percentage = (trigger['count'] / total_triggers * 100) if total_triggers > 0 else 0
            top_anxiety_triggers.append({
                'trigger': trigger['detected_phrase'],
                'percentage': round(percentage, 0)
            })
        
        data = {
            'total_recommendations': total_recommendations,
            'average_engagement_rate': round(avg_engagement, 2),
            'ai_accuracy_score': round(ai_accuracy, 2),
            'effectiveness_by_type': list(effectiveness_by_type),
            'weekly_recommendations': weekly_recommendations,
            'resources': AIResourceSerializer(resources, many=True).data,
            'top_anxiety_triggers': top_anxiety_triggers
        }
        
        return Response(data)


@extend_schema(tags=['System Admin'])
class ClientEngagementView(viewsets.ViewSet):
    """Client engagement and rewards dashboard"""
    permission_classes = [IsCompanyAdmin]
    serializer_class = ClientEngagementSerializer
    
    def list(self, request):
        # Get average daily engagement
        try:
            avg_engagement = ClientEngagement.objects.aggregate(
                avg_engagement=Avg('engagement_rate')
            )['avg_engagement'] or 0
        except Exception:
            avg_engagement = 0
        
        # Get active reward programs
        try:
            active_rewards = RewardProgram.objects.filter(is_active=True).count()
        except Exception:
            active_rewards = 0
        
        # Get total points awarded
        try:
            total_points = ClientEngagement.objects.aggregate(
                total_points=Sum('total_points')
            )['total_points'] or 0
        except Exception:
            total_points = 0
        
        # Get weekly engagement data (real data from last 7 days)
        from datetime import datetime, timedelta
        weekly_engagement = []
        for i in range(7):
            day = timezone.now() - timedelta(days=6-i)
            day_engagement = EngagementTracker.objects.filter(
                employee__user__last_login__date=day.date()
            ).count()
            weekly_engagement.append(day_engagement)
        
        # Get reward redemptions (real data from last 6 months)
        reward_redemptions = []
        for i in range(6):
            month_date = timezone.now() - timedelta(days=30*i)
            month_redemptions = RewardProgram.objects.filter(
                is_active=True,
                created_at__month=month_date.month,
                created_at__year=month_date.year
            ).aggregate(total=Sum('redemption_count'))['total'] or 0
            reward_redemptions.insert(0, month_redemptions)
        
        # Get clients
        clients = ClientEngagement.objects.select_related('organization').order_by('-total_points')[:10]
        
        # Get top rewards
        top_rewards = RewardProgram.objects.filter(is_active=True).order_by('-redemption_count')[:3]
        
        # Get engagement trends (real data based on time of day)
        from django.db.models import Q
        total_sessions = ChatSession.objects.count()
        morning_sessions = ChatSession.objects.filter(started_at__hour__gte=6, started_at__hour__lt=12).count()
        evening_sessions = ChatSession.objects.filter(started_at__hour__gte=18, started_at__hour__lt=24).count()
        weekend_sessions = ChatSession.objects.filter(started_at__week_day__in=[1, 7]).count()
        
        engagement_trends = [
            {'trend': 'Morning Sessions', 'percentage': round((morning_sessions / total_sessions * 100) if total_sessions > 0 else 0, 0)},
            {'trend': 'Evening Sessions', 'percentage': round((evening_sessions / total_sessions * 100) if total_sessions > 0 else 0, 0)},
            {'trend': 'Weekend Activity', 'percentage': round((weekend_sessions / total_sessions * 100) if total_sessions > 0 else 0, 0)}
        ]
        
        # Get streak statistics (real data)
        streak_7_plus = EngagementStreak.objects.filter(streak_count__gte=7).count()
        streak_14_plus = EngagementStreak.objects.filter(streak_count__gte=14).count()
        streak_30_plus = EngagementStreak.objects.filter(streak_count__gte=30).count()
        
        streak_stats = [
            {'streak': '7+ Day Streak', 'active_users': streak_7_plus},
            {'streak': '14+ Day Streak', 'active_users': streak_14_plus},
            {'streak': '30+ Day Streak', 'active_users': streak_30_plus}
        ]
        
        data = {
            'average_daily_engagement': round(avg_engagement, 2),
            'active_reward_programs': active_rewards,
            'total_points_awarded': total_points,
            'weekly_engagement': weekly_engagement,
            'reward_redemptions': reward_redemptions,
            'clients': ClientEngagementSerializer(clients, many=True).data,
            'top_rewards': RewardProgramSerializer(top_rewards, many=True).data,
            'engagement_trends': engagement_trends,
            'streak_statistics': streak_stats
        }
        
        return Response(data)


@extend_schema(tags=['System Admin'])
class ReportsAnalyticsView(viewsets.ViewSet):
    """Reports and analytics for system admin"""
    permission_classes = [IsCompanyAdmin]
    
    def list(self, request):
        from datetime import datetime, timedelta
        from django.db.models import Count
        platform_usage_chart = []
        for i in range(9):
            month_date = timezone.now() - timedelta(days=30*(8-i))
            month_users = User.objects.filter(
                last_login__month=month_date.month,
                last_login__year=month_date.year
            ).count()
            platform_usage_chart.append(month_users)
        
        total_assessments = MentalHealthAssessment.objects.count()
        health_conditions = []
        
        # Count anxiety cases (GAD-7)
        anxiety_count = MentalHealthAssessment.objects.filter(
            assessment_type__in=['GAD-7', 'BOTH'],
            gad7_total__gte=10
        ).count()
        
        # Count depression cases (PHQ-9)
        depression_count = MentalHealthAssessment.objects.filter(
            assessment_type__in=['PHQ-9', 'BOTH'],
            phq9_total__gte=10
        ).count()
        
        if total_assessments > 0:
            health_conditions = [
                {'condition': 'Anxiety', 'percentage': round((anxiety_count / total_assessments * 100), 0)},
                {'condition': 'Depression', 'percentage': round((depression_count / total_assessments * 100), 0)},
                {'condition': 'Other', 'percentage': round((100 - (anxiety_count / total_assessments * 100) - (depression_count / total_assessments * 100)), 0)}
            ]
        else:
            health_conditions = [
                {'condition': 'No data available', 'percentage': 0}
            ]
        
        # Get available reports
        available_reports = Report.objects.filter(is_active=True).order_by('-generated_date')[:5]
        
        # Get custom report options
        custom_report_types = [
            'Platform Usage',
            'Health Conditions',
            'Treatment Outcomes',
            'Organization Performance'
        ]
        
        date_ranges = [
            'Last 7 Days',
            'Last 30 Days',
            'Last 3 Months',
            'Last 6 Months',
            'Last Year'
        ]
        
        formats = ['PDF', 'Excel', 'CSV']
        
        data = {
            'platform_usage_chart': platform_usage_chart,
            'health_conditions_distribution': health_conditions,
            'available_reports': ReportSerializer(available_reports, many=True).data,
            'custom_report_types': custom_report_types,
            'date_ranges': date_ranges,
            'formats': formats
        }
        
        return Response(data)


@extend_schema(tags=['System Admin'])
class SystemSettingsView(viewsets.ModelViewSet):
    """System settings management"""
    queryset = SystemSettings.objects.all()
    serializer_class = SystemSettingsSerializer
    permission_classes = [IsCompanyAdmin]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['setting_name']
    ordering_fields = ['setting_name', 'updated_at']
    ordering = ['setting_name']




"""class FeatureFlagsView(viewsets.ModelViewSet):
    queryset = FeatureFlag.objects.all()
    serializer_class = FeatureFlagSerializer
    permission_classes = [IsCompanyAdmin]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'category', 'is_enabled']
    ordering = ['category', 'name']
    
    @action(detail=False, methods=['get'])
    def by_category(self, request):   
        categories = FeatureFlag.objects.values('category').annotate(
            count=Count('id'),
            enabled_count=Count('id', filter=models.Q(is_enabled=True))
        ).order_by('category')
        
        return Response(list(categories))"""




# views for educational resources
@extend_schema(tags=['Educational_Resources'])
class EducationalResourceViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = EducationalResource.objects.all()
    serializer_class = EducationalResourceSerializer
    permission_classes = [AllowAny]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']


class VideoViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Video.objects.filter(is_active=True)
    serializer_class = VideoSerializer
    permission_classes = [AllowAny]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['category']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'views', 'title']
    
    @action(detail=True, methods=['post'])
    def watch(self, request, pk=None):
        """Record that user watched this video"""
        video = self.get_object()
        video.views += 1
        video.save()
        
        # Track user activity if authenticated
        if request.user.is_authenticated:
            UserActivity.objects.create(user=request.user, video=video)
        
        return Response({'message': 'View recorded', 'total_views': video.views})
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def save(self, request, pk=None):
        """Save video to user's library"""
        video = self.get_object()
        saved, created = SavedResource.objects.get_or_create(
            user=request.user, 
            video=video
        )
        
        if created:
            return Response({'message': 'Video saved to your library'})
        else:
            saved.delete()
            return Response({'message': 'Video removed from library'})
    
    @action(detail=False, methods=['get'])
    def popular(self, request):
       
        popular = self.queryset.order_by('-views')[:10]
        serializer = self.get_serializer(popular, many=True)
        return Response(serializer.data)


class AudioViewSet(viewsets.ReadOnlyModelViewSet):
   
    queryset = Audio.objects.filter(is_active=True)
    serializer_class = AudioSerializer
    permission_classes = [AllowAny]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['category']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'plays', 'title']
    
    @action(detail=True, methods=['post'])
    def play(self, request, pk=None):
        
        audio = self.get_object()
        audio.plays += 1
        audio.save()
        
        # Track user activity if authenticated
        if request.user.is_authenticated:
            UserActivity.objects.create(user=request.user, audio=audio)
        
        return Response({'message': 'Play recorded', 'total_plays': audio.plays})
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def save(self, request, pk=None):
        audio = self.get_object()
        saved, created = SavedResource.objects.get_or_create(
            user=request.user, 
            audio=audio
        )
        
        if created:
            return Response({'message': 'Audio saved to your library'})
        else:
            saved.delete()
            return Response({'message': 'Audio removed from library'})


class ArticleViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Article.objects.filter(is_published=True)
    serializer_class = ArticleSerializer
    permission_classes = [AllowAny]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['category']
    search_fields = ['title', 'content', 'excerpt']
    ordering_fields = ['published_date', 'views', 'reading_time']
    lookup_field = 'slug'
    
    @action(detail=True, methods=['post'])
    def read(self, request, slug=None):
        article = self.get_object()
        article.views += 1
        article.save()
        
        # Track user activity if authenticated
        if request.user.is_authenticated:
            UserActivity.objects.create(user=request.user, article=article)
        
        return Response({'message': 'Read recorded', 'total_views': article.views})
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def save(self, request, slug=None):
        article = self.get_object()
        saved, created = SavedResource.objects.get_or_create(
            user=request.user, 
            article=article
        )
        
        if created:
            return Response({'message': 'Article saved to your library'})
        else:
            saved.delete()
            return Response({'message': 'Article removed from library'})
    
    @action(detail=False, methods=['get'])
    def trending(self, request):
        trending = self.queryset.order_by('-views')[:10]
        serializer = self.get_serializer(trending, many=True)
        return Response(serializer.data)


class MeditationTechniqueViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = MeditationTechnique.objects.filter(is_active=True)
    serializer_class = MeditationTechniqueSerializer
    permission_classes = [AllowAny]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['category', 'difficulty']
    search_fields = ['title', 'description', 'benefits']
    ordering_fields = ['difficulty', 'duration', 'times_practiced']
    
    @action(detail=True, methods=['post'])
    def practice(self, request, pk=None):
        meditation = self.get_object()
        meditation.times_practiced += 1
        meditation.save()
        
        # Track user activity if authenticated
        if request.user.is_authenticated:
            UserActivity.objects.create(user=request.user, meditation=meditation, completed=True)
        
        return Response({'message': 'Practice recorded', 'total_sessions': meditation.times_practiced})
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def save(self, request, pk=None):
        meditation = self.get_object()
        saved, created = SavedResource.objects.get_or_create(
            user=request.user, 
            meditation=meditation
        )
        
        if created:
            return Response({'message': 'Meditation saved to your library'})
        else:
            saved.delete()
            return Response({'message': 'Meditation removed from library'})
    
    @action(detail=False, methods=['get'])
    def for_beginners(self, request):
        beginners = self.queryset.filter(difficulty='beginner')
        serializer = self.get_serializer(beginners, many=True)
        return Response(serializer.data)


class SavedResourceViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = SavedResourceSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return SavedResource.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['get'])
    def by_type(self, request):
        resource_type = request.query_params.get('type', 'all')
        saved = self.get_queryset()
        
        if resource_type == 'videos':
            saved = saved.filter(video__isnull=False)
        elif resource_type == 'audios':
            saved = saved.filter(audio__isnull=False)
        elif resource_type == 'articles':
            saved = saved.filter(article__isnull=False)
        elif resource_type == 'meditations':
            saved = saved.filter(meditation__isnull=False)
        
        serializer = self.get_serializer(saved, many=True)
        return Response(serializer.data)


class UserActivityViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = UserActivitySerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return UserActivity.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        activities = self.get_queryset()
        
        stats = {
            'total_activities': activities.count(),
            'videos_watched': activities.filter(video__isnull=False).count(),
            'audios_played': activities.filter(audio__isnull=False).count(),
            'articles_read': activities.filter(article__isnull=False).count(),
            'meditations_practiced': activities.filter(meditation__isnull=False, completed=True).count(),
        }
        
        return Response(stats)



@extend_schema(
    request=OnboardingStateSerializer,
    responses=OnboardingStateSerializer,
    methods=["GET", "PATCH"]
)
class OnboardingView(RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = OnboardingStateSerializer

    def get_object(self):
        obj, _ = OnboardingState.objects.get_or_create(user=self.request.user)
        return obj

# POST to mark onboarding as complete
@extend_schema(
    request=None,
    responses={200: {"message": "Onboarding completed."}, 404: {"error": "Onboarding state not found."}},
    methods=["POST"]
)
class CompleteOnboardingView(UpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = OnboardingStateSerializer

    def get_object(self):
        try:
            return OnboardingState.objects.get(user=self.request.user)
        except OnboardingState.DoesNotExist:
            return None

    def update(self, request, *args, **kwargs):
        state = self.get_object()
        if not state:
            return Response({'error': 'Onboarding state not found.'}, status=404)
        state.completed = True
        state.save()
        return Response({'message': 'Onboarding completed.'})




@extend_schema_view(
    list=extend_schema(tags=['Dynamic Questions']),
    retrieve=extend_schema(tags=['Dynamic Questions']),
    random=extend_schema(
        description="Returns a random set of active dynamic questions.",
        responses=DynamicQuestionSerializer(many=True),
        tags=['Dynamic Questions']
    )
)
class DynamicQuestionViewSet(viewsets.ModelViewSet):
    queryset = DynamicQuestion.objects.filter(is_active=True)
    serializer_class = DynamicQuestionSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['get'])
    def random(self, request):
        count = int(request.query_params.get('count', 5))
        questions = list(self.queryset.order_by('?')[:count])
        serializer = self.get_serializer(questions, many=True)
        return Response(serializer.data)
