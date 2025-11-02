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
from rest_framework.permissions import (
    IsAuthenticated,
    BasePermission,
    IsAuthenticatedOrReadOnly,
    AllowAny,
)
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from obeeomaapp.serializers import *
from obeeomaapp.models import *
from django.core.mail import send_mail, EmailMultiAlternatives
from .utils.gmail_http_api import send_gmail_api_email
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import secrets
from rest_framework import filters
import string
from django.template.loader import render_to_string
import logging
from django_filters.rest_framework import DjangoFilterBackend

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny



from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer
from .models import User, Employer, Employee, Subscription, RecentActivity, HotlineActivity, EmployeeEngagement, AIManagement, PasswordResetToken
""" from .models import AnxietyDistressMastery, DepressionOvercome, ClassicalArticle, CustomerGeneratedContent
from .serializers import (
     AnxietyDistressMasterySerializer, 
     DepressionOvercomeSerializer, 
#     ClassicalArticleSerializer, 
#     CustomerGeneratedContentSerializer
# )"""


# Set up logging
logger = logging.getLogger(__name__)

# Get User model
User = get_user_model()

# --- Permission: company admin (is_staff) ---
class IsCompanyAdmin(BasePermission):
    """Allows access only to users with is_staff=True."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_staff)


# --- Authentication Views ---
class SignupView(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = SignupSerializer
    permission_classes = [permissions.AllowAny]


# Employer Registration View
@extend_schema(
    tags=["Authentication"],
    request=EmployerRegistrationSerializer,
    responses={
        201: {
            "description": "Organization created successfully",
            "content": {
                "application/json": {
                    "example": {
                        "message": "Organization created successfully",
                        "organization": {
                            "id": 1,
                            "name": "My Company Inc",
                            "is_active": True,
                            "joined_date": "2025-10-30T18:50:48Z"
                        },
                        "employee": {
                            "id": 1,
                            "name": "John Doe",
                            "email": "john@example.com",
                            "status": "active"
                        }
                    }
                }
            }
        },
        400: {"description": "Bad Request - organization_name required or user already has organization"}
    },
    description="Create an organization for the authenticated employer user. Each user can only create one organization."
)
class EmployerRegistrationView(APIView):
    """
    Allow employers to register and create their organization in one step.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Create an organization for the authenticated employer user."""
        serializer = EmployerRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        organization_name = serializer.validated_data.get('organization_name')
        industry = serializer.validated_data.get('industry', '')
        size = serializer.validated_data.get('size', '')
        
        # Check if user already has an organization
        existing_org = Employer.objects.filter(
            employees__user=request.user
        ).first()
        
        if existing_org:
            return Response(
                {
                    "error": "You already have an organization",
                    "organization": EmployerSerializer(existing_org).data
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create the organization
        employer = Employer.objects.create(
            name=organization_name,
            is_active=True
        )
        
        # Link the user to this organization as an employee
        employee = Employee.objects.create(
            employer=employer,
            user=request.user,
            first_name=request.user.first_name or request.user.username,
            last_name=request.user.last_name or '',
            email=request.user.email,
            status='active'
        )
        
        # Create a recent activity log
        RecentActivity.objects.create(
            employer=employer,
            activity_type="New Employer",
            details=f"Organization '{organization_name}' was created by {request.user.username}",
            is_important=True
        )
        
        return Response(
            {
                "message": "Organization created successfully",
                "organization": EmployerSerializer(employer).data,
                "employee": EmployeeSerializer(employee).data
            },
            status=status.HTTP_201_CREATED
        )


# login view
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        user = authenticate(request=request, username=username, password=password)

        if not user:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        if not user.is_active:
            return Response({"detail": "Account is disabled"}, status=status.HTTP_403_FORBIDDEN)

        # This helps to Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "date_joined": user.date_joined,
            "is_active": user.is_active,
            "avatar": user.avatar.url if hasattr(user, 'avatar') and user.avatar else None,
        }

        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": user_data
        })


    
# matching view for custom token obtain pair serializer
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

logger = logging.getLogger(__name__)

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
            expires_at = timezone.now() + timedelta(minutes=15)

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

This code will expire in 15 minutes.

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


class PasswordChangeView(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordChangeSerializer

    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        if not user.check_password(serializer.validated_data['old_password']):
            return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({"message": "Password updated successfully"})


# --- Admin Dashboard ---
class OverviewView(viewsets.ViewSet):
    permission_classes = [IsCompanyAdmin]

    def list(self, request):
        employer_count = Employer.objects.count()
        employee_count = Employee.objects.count()
        active_subscriptions = Subscription.objects.filter(is_active=True).count()
        recent = RecentActivity.objects.select_related("employer").order_by("-timestamp")[:10]
        recent_serialized = RecentActivitySerializer(recent, many=True).data
        return Response({
            "employer_count": employer_count,
            "employee_count": employee_count,
            "active_subscriptions": active_subscriptions,
            "recent_activities": recent_serialized,
        })


class TrendsView(viewsets.ReadOnlyModelViewSet):
    queryset = HotlineActivity.objects.select_related("employer").order_by("-recorded_at")
    serializer_class = HotlineActivitySerializer
    permission_classes = [IsCompanyAdmin]


class EmployeeEngagementView(viewsets.ModelViewSet):
    queryset = EmployeeEngagement.objects.select_related("employer").order_by("-month")
    serializer_class = EmployeeEngagementSerializer
    permission_classes = [IsCompanyAdmin]


class FeaturesUsageView(viewsets.ModelViewSet):
    queryset = AIManagement.objects.select_related("employer").order_by("-created_at")
    serializer_class = AIManagementSerializer
    permission_classes = [IsCompanyAdmin]

    @action(detail=False, methods=['get'])
    def by_category(self, request):
        # Replace this with your actual logic
        return Response({"message": "Feature flags grouped by category"})

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
    permission_classes = [IsCompanyAdmin]

    def get_queryset(self):
        # Get invitations for the employer's organization
        if hasattr(self.request.user, 'employer_profile'):
            return EmployeeInvitation.objects.filter(
                employer=self.request.user.employer_profile.employer
            ).order_by('-created_at')
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
        
        # Try to get employer from employee profile
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
            try:
                email_sent = send_gmail_api_email(invitation.email, subject, message)
            except Exception as gmail_error:
                logger.warning(f"Gmail API failed, using SMTP: {str(gmail_error)}")
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [invitation.email],
                    fail_silently=False,
                )
                email_sent = True
            
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


class UsersView(viewsets.ModelViewSet):
    queryset = Employee.objects.select_related("employer").all()
    serializer_class = EmployeeSerializer
    permission_classes = [IsCompanyAdmin]


class ReportsView(viewsets.ReadOnlyModelViewSet):
    queryset = RecentActivity.objects.select_related("employer").order_by("-timestamp")
    serializer_class = RecentActivitySerializer
    permission_classes = [IsCompanyAdmin]


class CrisisInsightsView(viewsets.ReadOnlyModelViewSet):
    queryset = HotlineActivity.objects.select_related("employer").order_by("-recorded_at")
    serializer_class = HotlineActivitySerializer
    permission_classes = [IsCompanyAdmin]


def home(request):
    return JsonResponse({"status": "ok", "app": "obeeomaapp"})


class EmailConfigCheckView(APIView):
    """Debug endpoint to check email configuration"""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        config = {
            "email_backend": settings.EMAIL_BACKEND,
            "email_host": settings.EMAIL_HOST,
            "email_port": settings.EMAIL_PORT,
            "email_use_tls": settings.EMAIL_USE_TLS,
            "email_use_ssl": settings.EMAIL_USE_SSL,
            "email_host_user": settings.EMAIL_HOST_USER,
            "default_from_email": settings.DEFAULT_FROM_EMAIL,
            "debug_mode": settings.DEBUG,
            "has_email_password": bool(settings.EMAIL_HOST_PASSWORD),
        }
        return Response(config)




# ---- Employee-specific APIs ----



class EmployeeViewSetMixin:
    """Base mixin for all employee-related viewsets"""
    
    def get_employee(self):
        """Get employee profile for current user"""
        try:
            return EmployeeProfile.objects.get(user=self.request.user)
        except EmployeeProfile.DoesNotExist:
            raise ValidationError({
                "error": "Profile not found. Please create your profile first."
            })
    
    def perform_create(self, serializer):
        """Auto-assign employee when creating"""
        employee = self.get_employee()
        serializer.save(employee=employee)


class EmployeeProfileViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['subscription_tier', 'is_premium_active']
    search_fields = ['organization', 'role']

    def get_queryset(self):
        return EmployeeProfile.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        if self.action == 'create':
            return EmployeeProfileCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return EmployeeProfileUpdateSerializer
        elif self.action == 'set_wellness_status':
            return WellnessStatusSerializer
        return EmployeeProfileSerializer

    def perform_create(self, serializer):
        if EmployeeProfile.objects.filter(user=self.request.user).exists():
            raise ValidationError({
                "error": "You already have a profile. Use PUT or PATCH to update it."
            })
        serializer.save(user=self.request.user)

    @action(detail=False, methods=['get'])
    def me(self, request):
        try:
            profile = EmployeeProfile.objects.get(user=request.user)
            serializer = self.get_serializer(profile)
            return Response(serializer.data)
        except EmployeeProfile.DoesNotExist:
            return Response({
                "error": "Profile not found. Please create one first."
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['patch'], url_path='set-wellness-status')
    def set_wellness_status(self, request, pk=None):
        profile = self.get_object()
        serializer = WellnessStatusSerializer(profile, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            'message': 'Wellness status updated successfully',
            'data': serializer.data
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=['delete'], url_path='delete-account')
    def delete_account(self, request, pk=None):
        profile = self.get_object()
        user = profile.user
        profile.delete()
        user.delete()
        return Response({
            "detail": "Your account and profile were deleted successfully."
        }, status=status.HTTP_204_NO_CONTENT)


class AvatarProfileViewSet(viewsets.ModelViewSet, EmployeeViewSetMixin):
    serializer_class = AvatarProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return AvatarProfile.objects.filter(employee__user=self.request.user)


class WellnessHubViewSet(viewsets.ModelViewSet, EmployeeViewSetMixin):
    serializer_class = WellnessHubSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return WellnessHub.objects.filter(employee__user=self.request.user)


class AssessmentResultViewSet(viewsets.ModelViewSet, EmployeeViewSetMixin):
    serializer_class = AssessmentResultSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return AssessmentResult.objects.filter(employee__user=self.request.user)


class CrisisTriggerViewSet(viewsets.ModelViewSet, EmployeeViewSetMixin):
    serializer_class = CrisisTriggerSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return CrisisTrigger.objects.filter(employee__user=self.request.user)


class NotificationViewSet(viewsets.ModelViewSet, EmployeeViewSetMixin):
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['is_read', 'notification_type']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        return Notification.objects.filter(employee__user=self.request.user)

    @action(detail=False, methods=['get'])
    def unread(self, request):
        unread = self.get_queryset().filter(is_read=False)
        serializer = self.get_serializer(unread, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def mark_all_read(self, request):
        updated = self.get_queryset().filter(is_read=False).update(is_read=True)
        return Response({
            'message': f'{updated} notifications marked as read',
            'count': updated
        })

    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        notification = self.get_object()
        notification.is_read = True
        notification.save()
        return Response({
            'message': 'Notification marked as read',
            'notification': self.get_serializer(notification).data
        })

    @action(detail=False, methods=['get'])
    def count_unread(self, request):
        count = self.get_queryset().filter(is_read=False).count()
        return Response({'unread_count': count})


class EngagementTrackerViewSet(viewsets.ModelViewSet, EmployeeViewSetMixin):
    serializer_class = EngagementTrackerSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return EngagementTracker.objects.filter(employee__user=self.request.user)


class FeedbackViewSet(viewsets.ModelViewSet, EmployeeViewSetMixin):
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


class ChatSessionViewSet(viewsets.ModelViewSet, EmployeeViewSetMixin):
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


class ChatMessageViewSet(viewsets.ModelViewSet):
    serializer_class = ChatMessageSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['created_at']
    ordering = ['created_at']

    def get_queryset(self):
        return ChatMessage.objects.filter(session__employee__user=self.request.user)

    def perform_create(self, serializer):
        session_id = self.request.data.get('session')
        if not session_id:
            raise ValidationError({"session": "Session ID is required"})
        try:
            session = ChatSession.objects.get(
                id=session_id,
                employee__user=self.request.user
            )
            serializer.save(session=session)
            session.last_message_at = timezone.now()
            session.save()
        except ChatSession.DoesNotExist:
            raise ValidationError({"session": "Invalid session ID"})

    @action(detail=False, methods=['get'])
    def by_session(self, request):
        session_id = request.query_params.get('session_id')
        if not session_id:
            return Response({
                "error": "session_id parameter required"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        messages = self.get_queryset().filter(session_id=session_id)
        serializer = self.get_serializer(messages, many=True)
        return Response(serializer.data)


class RecommendationLogViewSet(viewsets.ModelViewSet, EmployeeViewSetMixin):
    serializer_class = RecommendationLogSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return RecommendationLog.objects.filter(employee__user=self.request.user)

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

class MyBadgesView(viewsets.ReadOnlyModelViewSet):
    serializer_class = UserBadgeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return UserBadge.objects.filter(user=self.request.user)


class MyStreaksView(viewsets.ReadOnlyModelViewSet):
    serializer_class = EngagementStreakSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return EngagementStreak.objects.filter(user=self.request.user).order_by('-last_active_date')


# --- Employer APIs ---
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


class TestsByTypeView(viewsets.ViewSet):
    """Tests by type analytics"""
    permission_classes = [IsCompanyAdmin]
    
    def list(self, request):
        tests_by_type = WellnessTest.objects.values('test_type').annotate(
            count=Count('id')
        ).order_by('-count')
        
        return Response(list(tests_by_type))


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


class OrganizationsManagementView(viewsets.ModelViewSet):
    """Organizations management for system admin"""
    queryset = Employer.objects.all()
    serializer_class = OrganizationsManagementSerializer
    permission_classes = [IsCompanyAdmin]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name']
    ordering_fields = ['name', 'joined_date']
    ordering = ['-joined_date']
    
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


class ReportsAnalyticsView(viewsets.ViewSet):
    """Reports and analytics for system admin"""
    permission_classes = [IsCompanyAdmin]
    
    def list(self, request):
        # Get platform usage chart data (real data from last 9 months)
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
        
        # Get health conditions distribution (real data from assessments)
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
class ResourceCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ResourceCategory.objects.all()
    serializer_class = ResourceCategorySerializer
    permission_classes = [AllowAny]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['name']


class EducationalVideoViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = EducationalVideo.objects.filter(is_active=True)
    serializer_class = EducationalVideoSerializer
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


class CalmingAudioViewSet(viewsets.ReadOnlyModelViewSet):
   
    queryset = CalmingAudio.objects.filter(is_active=True)
    serializer_class = CalmingAudioSerializer
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


class MentalHealthArticleViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = MentalHealthArticle.objects.filter(is_published=True)
    serializer_class = MentalHealthArticleSerializer
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
