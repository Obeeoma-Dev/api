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
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework_simplejwt.tokens import RefreshToken
from obeeomaapp.serializers import *
from obeeomaapp.models import *
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import secrets
from rest_framework import filters
import string
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
import logging


from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from django.db.models import Q
from .models import User, Employer, Employee, Subscription, RecentActivity, HotlineActivity, EmployeeEngagement, AIManagement, PasswordResetToken
"""from .models import AnxietyDistressMastery, DepressionOvercome, ClassicalArticle, CustomerGeneratedContent
# from .serializers import (
#     AnxietyDistressMasterySerializer, 
#     DepressionOvercomeSerializer, 
#     ClassicalArticleSerializer, 
#     CustomerGeneratedContentSerializer
# )"""


# Set up logging
logger = logging.getLogger(__name__)
from obeeomaapp.serializers import *


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

# login view
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = authenticate(
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password']
        )
        
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "username": user.username,
                "role": user.role  # <-- just add this line
            })
        
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    
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

        # Step 3: Send email safely
        try:
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
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )

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


class InviteView(viewsets.ModelViewSet):
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer
    permission_classes = [IsCompanyAdmin]


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


# --- Employee App ---
class EmployeeProfileView(viewsets.ModelViewSet):
    serializer_class = EmployeeProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return EmployeeProfile.objects.filter(user=self.request.user)


class AvatarProfileView(viewsets.ModelViewSet):
    serializer_class = AvatarProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return AvatarProfile.objects.filter(employee__user=self.request.user)


class WellnessHubView(viewsets.ModelViewSet):
    serializer_class = WellnessHubSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return WellnessHub.objects.filter(employee__user=self.request.user)


class MoodCheckInView(viewsets.ModelViewSet):
    serializer_class = MoodCheckInSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return MoodCheckIn.objects.filter(employee__user=self.request.user)

    def perform_create(self, serializer):
        employee = get_object_or_404(EmployeeProfile, user=self.request.user)
        serializer.save(employee=employee)


class AssessmentResultView(viewsets.ModelViewSet):
    serializer_class = AssessmentResultSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return AssessmentResult.objects.filter(employee__user=self.request.user)

    def perform_create(self, serializer):
        employee = get_object_or_404(EmployeeProfile, user=self.request.user)
        serializer.save(employee=employee)


class SelfHelpResourceView(viewsets.ModelViewSet):
    queryset = SelfHelpResource.objects.all()
    serializer_class = SelfHelpResourceSerializer
    permission_classes = [permissions.IsAuthenticated]


class EducationalResourceView(viewsets.ModelViewSet):
    queryset = EducationalResource.objects.all()
    serializer_class = EducationalResourceSerializer
    permission_classes = [permissions.IsAuthenticated]


class CrisisTriggerView(viewsets.ModelViewSet):
    serializer_class = CrisisTriggerSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return CrisisTrigger.objects.filter(employee__user=self.request.user)

    def perform_create(self, serializer):
        employee = get_object_or_404(EmployeeProfile, user=self.request.user)
        serializer.save(employee=employee)


class NotificationView(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(employee__user=self.request.user)


class EngagementTrackerView(viewsets.ModelViewSet):
    serializer_class = EngagementTrackerSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return EngagementTracker.objects.filter(employee__user=self.request.user)


class FeedbackView(viewsets.ModelViewSet):
    serializer_class = FeedbackSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Feedback.objects.filter(employee__user=self.request.user)

    def perform_create(self, serializer):
        employee = get_object_or_404(EmployeeProfile, user=self.request.user)
        serializer.save(employee=employee)


class ChatSessionView(viewsets.ModelViewSet):
    serializer_class = ChatSessionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return ChatSession.objects.filter(employee__user=self.request.user)

    def perform_create(self, serializer):
        employee = get_object_or_404(EmployeeProfile, user=self.request.user)
        serializer.save(employee=employee)


class ChatMessageView(viewsets.ModelViewSet):
    serializer_class = ChatMessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        session_id = self.kwargs.get("session_id")
        return ChatMessage.objects.filter(session__id=session_id, session__employee__user=self.request.user)

    def perform_create(self, serializer):
        session = get_object_or_404(ChatSession, id=self.kwargs.get("session_id"), employee__user=self.request.user)
        serializer.save(session=session)


class RecommendationLogView(viewsets.ModelViewSet):
    serializer_class = RecommendationLogSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return RecommendationLog.objects.filter(employee__user=self.request.user)

    def perform_create(self, serializer):
        employee = get_object_or_404(EmployeeProfile, user=self.request.user)
        serializer.save(employee=employee)


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
    permission_classes = [IsCompanyAdmin]

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


class InvitationAcceptView(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]
    serializer_class = EmployeeInvitationAcceptSerializer

    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        return Response({'message': 'Account created successfully', 'access': str(refresh.access_token), 'refresh': str(refresh)}, status=status.HTTP_201_CREATED)

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
class ResourceCategoryViewSet(viewsets.ModelViewSet):
    """Mental health resource categories (Stress, Anxiety, Sleep, etc.)"""
    queryset = ResourceCategory.objects.all()
    serializer_class = ResourceCategorySerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']


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
    search_fields = ['name', 'email', 'department__name']
    ordering_fields = ['name', 'email', 'joined_date', 'status']
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


class DepartmentManagementView(viewsets.ModelViewSet):
    """Department management"""
    queryset = Department.objects.select_related('employer').all()
    serializer_class = DepartmentSerializer
    permission_classes = [IsCompanyAdmin]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']


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
        from django.db.models import Count
        
        tests_by_type = WellnessTest.objects.values('test_type').annotate(
            count=Count('id')
        ).order_by('-count')
        
        return Response(list(tests_by_type))


class TestsByDepartmentView(viewsets.ViewSet):
    """Tests by department analytics"""
    permission_classes = [IsCompanyAdmin]
    
    def list(self, request):
        from django.db.models import Count
        
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
    
    def list(self, request):
        # Get platform metrics
        try:
            latest_metrics = PlatformMetrics.objects.first()
            if not latest_metrics:
                # Create default metrics if none exist
                latest_metrics = PlatformMetrics.objects.create(
                    total_organizations=Employer.objects.count(),
                    total_clients=Employee.objects.count(),
                    monthly_revenue=0.00,
                    hotline_calls_today=0
                )
        except Exception:
            # Fallback if PlatformMetrics doesn't exist yet
            latest_metrics = type('obj', (object,), {
                'total_organizations': Employer.objects.count(),
                'total_clients': Employee.objects.count(),
                'monthly_revenue': 0.00,
                'hotline_calls_today': 0,
                'organizations_this_month': 0,
                'clients_this_month': 0,
                'revenue_growth_percentage': 0.00,
                'hotline_growth_percentage': 0.00
            })()
        
        # Get platform usage data
        try:
            platform_usage = PlatformUsage.objects.all()[:6]
        except Exception:
            platform_usage = []
        
        # Get subscription revenue data
        try:
            subscription_revenue = SubscriptionRevenue.objects.all()[:9]
        except Exception:
            subscription_revenue = []
        
        # Get recent system activities
        try:
            recent_activities = SystemActivity.objects.select_related('organization').order_by('-created_at')[:5]
        except Exception:
            recent_activities = []
        
        data = {
            'total_organizations': latest_metrics.total_organizations,
            'total_clients': latest_metrics.total_clients,
            'monthly_revenue': latest_metrics.monthly_revenue,
            'hotline_calls_today': latest_metrics.hotline_calls_today,
            'organizations_this_month': latest_metrics.organizations_this_month,
            'clients_this_month': latest_metrics.clients_this_month,
            'revenue_growth_percentage': latest_metrics.revenue_growth_percentage,
            'hotline_growth_percentage': latest_metrics.hotline_growth_percentage,
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
    
    def list(self, request):
        # Get today's calls
        try:
            today_calls = HotlineCall.objects.filter(call_date__date=timezone.now().date()).count()
        except Exception:
            today_calls = 0
        
        # Get average duration
        try:
            avg_duration = HotlineCall.objects.aggregate(
                avg_duration=Avg('duration_minutes')
            )['avg_duration'] or 0
        except Exception:
            avg_duration = 0
        
        # Get active operators (mock data for now)
        active_operators = 8
        
        # Get hourly volume data (mock data)
        hourly_volume = [2, 4, 6, 8, 12, 15, 18, 20, 16, 14, 10, 8, 6, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7]
        
        # Get call reasons distribution
        try:
            from django.db.models import Count
            call_reasons = HotlineCall.objects.values('reason').annotate(
                count=Count('id')
            ).order_by('-count')
        except Exception:
            call_reasons = []
        
        # Get recent calls
        try:
            recent_calls = HotlineCall.objects.select_related('organization').order_by('-call_date')[:10]
        except Exception:
            recent_calls = []
        
        # Get critical cases
        try:
            critical_cases = HotlineCall.objects.filter(
                urgency='critical'
            ).select_related('organization').order_by('-call_date')[:5]
        except Exception:
            critical_cases = []
        
        # Get operator performance (mock data)
        operator_performance = [
            {'name': 'John Smith', 'calls': 12, 'resolution_rate': 92},
            {'name': 'Emily Johnson', 'calls': 9, 'resolution_rate': 88},
            {'name': 'Michael Brown', 'calls': 10, 'resolution_rate': 85},
            {'name': 'Sarah Davis', 'calls': 11, 'resolution_rate': 90}
        ]
        
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
        
        # Get weekly recommendations (mock data)
        weekly_recommendations = [120, 130, 120, 140, 145, 135]
        
        # Get resources
        try:
            resources = AIResource.objects.all()[:10]
        except Exception:
            resources = []
        
        # Get top anxiety triggers (mock data)
        top_anxiety_triggers = [
            {'trigger': 'Work-related stress', 'percentage': 78},
            {'trigger': 'Social situations', 'percentage': 65},
            {'trigger': 'Health concerns', 'percentage': 58},
            {'trigger': 'Financial pressure', 'percentage': 52},
            {'trigger': 'Family relationships', 'percentage': 46}
        ]
        
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
        
        # Get weekly engagement data (mock data)
        weekly_engagement = [65, 70, 68, 75, 80, 85, 78]
        
        # Get reward redemptions (mock data)
        reward_redemptions = [25, 30, 35, 40, 45, 40]
        
        # Get clients
        try:
            clients = ClientEngagement.objects.select_related('organization').all()[:10]
        except Exception:
            clients = []
        
        # Get top rewards
        try:
            top_rewards = RewardProgram.objects.filter(is_active=True).order_by('-redemption_count')[:3]
        except Exception:
            top_rewards = []
        
        # Get engagement trends (mock data)
        engagement_trends = [
            {'trend': 'Morning Sessions', 'percentage': 68},
            {'trend': 'Evening Sessions', 'percentage': 42},
            {'trend': 'Weekend Activity', 'percentage': 55}
        ]
        
        # Get streak statistics
        streak_stats = [
            {'streak': '7+ Day Streak', 'active_users': 324},
            {'streak': '14+ Day Streak', 'active_users': 186},
            {'streak': '30+ Day Streak', 'active_users': 78}
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
        # Get platform usage chart data (mock data)
        platform_usage_chart = [60, 70, 80, 90, 100, 110, 120, 130, 140]
        
        # Get health conditions distribution (mock data)
        health_conditions = [
            {'condition': 'Anxiety', 'percentage': 33},
            {'condition': 'Depression', 'percentage': 28},
            {'condition': 'PTSD', 'percentage': 12},
            {'condition': 'Bipolar', 'percentage': 8},
            {'condition': 'ADHD', 'percentage': 6},
            {'condition': 'OCD', 'percentage': 5},
            {'condition': 'Other', 'percentage': 5}
        ]
        
        # Get available reports
        try:
            available_reports = Report.objects.filter(is_active=True).order_by('-generated_date')[:5]
        except Exception:
            available_reports = []
        
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

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import EducationalVideo, UserVideoInteraction, ResourceCategory
from .serializers import (
    EducationalVideoSerializer, 
    UserVideoInteractionSerializer,
    ResourceCategorySerializer
)

class EducationalVideoViewSet(viewsets.ModelViewSet):
    queryset = EducationalVideo.objects.filter(is_active=True)
    serializer_class = EducationalVideoSerializer
    permission_classes = [AllowAny]

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [IsAuthenticated()]
        return [AllowAny()]

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def mark_helpful(self, request, pk=None):
        video = self.get_object()
        video.helpful_count += 1
        video.save()
        return Response({'status': 'marked helpful', 'helpful_count': video.helpful_count})

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def save_video(self, request, pk=None):
        video = self.get_object()
        video.saved_count += 1
        video.save()
        return Response({'status': 'video saved', 'saved_count': video.saved_count})

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.views_count += 1
        instance.save()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

class UserVideoInteractionViewSet(viewsets.ModelViewSet):
    serializer_class = UserVideoInteractionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserVideoInteraction.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class ResourceCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ResourceCategory.objects.all()
    serializer_class = ResourceCategorySerializer
    permission_classes = [AllowAny] 
    permission_classes = [AllowAny]

# # Anxiety Distress Mastery API
# class AnxietyDistressMasteryViewSet(viewsets.ModelViewSet):
#     permission_classes = [IsAuthenticated]
#     serializer_class = AnxietyDistressMasterySerializer
    
#     def get_queryset(self):
#         return AnxietyDistressMastery.objects.filter(user=self.request.user)
    
#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)
    
#     @action(detail=True, methods=['post'])
#     def mark_completed(self, request, pk=None):
#         mastery = self.get_object()
#         mastery.progress_status = 'completed'
#         mastery.save()
#         serializer = self.get_serializer(mastery)
#         return Response(serializer.data)
    
#     @action(detail=False, methods=['get'])
#     def progress_stats(self, request):
#         queryset = self.get_queryset()
#         total = queryset.count()
#         completed = queryset.filter(progress_status='completed').count()
#         in_progress = queryset.filter(progress_status='in_progress').count()
        
#         return Response({
#             'total': total,
#             'completed': completed,
#             'in_progress': in_progress,
#             'completion_rate': (completed / total * 100) if total > 0 else 0
#         })

# # Depression Overcome API
# class DepressionOvercomeViewSet(viewsets.ModelViewSet):
#     permission_classes = [IsAuthenticated]
#     serializer_class = DepressionOvercomeSerializer
    
#     def get_queryset(self):
#         return DepressionOvercome.objects.filter(user=self.request.user)
    
#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)
    
#     @action(detail=True, methods=['post'])
#     def complete_activity(self, request, pk=None):
#         activity = self.get_object()
#         mood_change = request.data.get('mood_change', 0)
        
#         activity.is_completed = True
#         activity.actual_mood_change = mood_change
#         activity.save()
        
#         serializer = self.get_serializer(activity)
#         return Response(serializer.data)
    
#     @action(detail=False, methods=['get'])
#     def by_type(self, request):
#         activity_type = request.query_params.get('type', None)
#         if activity_type:
#             queryset = self.get_queryset().filter(activity_type=activity_type)
#             serializer = self.get_serializer(queryset, many=True)
#             return Response(serializer.data)
#         return Response({"error": "Type parameter required"}, status=400)

# # Classical Articles API
# class ClassicalArticleViewSet(viewsets.ReadOnlyModelViewSet):
#     permission_classes = [IsAuthenticatedOrReadOnly]
#     serializer_class = ClassicalArticleSerializer
#     queryset = ClassicalArticle.objects.all()
    
#     @action(detail=False, methods=['get'])
#     def featured(self, request):
#         featured_articles = self.get_queryset().filter(is_featured=True)
#         serializer = self.get_serializer(featured_articles, many=True)
#         return Response(serializer.data)
    
#     @action(detail=False, methods=['get'])
#     def by_category(self, request):
#         category = request.query_params.get('category', None)
#         if category:
#             articles = self.get_queryset().filter(category=category)
#             serializer = self.get_serializer(articles, many=True)
#             return Response(serializer.data)
#         return Response({"error": "Category parameter required"}, status=400)
    
#     @action(detail=True, methods=['get'])
#     def similar(self, request, pk=None):
#         article = self.get_object()
#         similar_articles = self.get_queryset().filter(
#             category=article.category
#         ).exclude(id=article.id)[:5]
#         serializer = self.get_serializer(similar_articles, many=True)
#         return Response(serializer.data)

# # Customer Generated Content API
# class CustomerGeneratedContentViewSet(viewsets.ModelViewSet):
#     permission_classes = [IsAuthenticatedOrReadOnly]
#     serializer_class = CustomerGeneratedContentSerializer
    
#     def get_queryset(self):
#         if self.request.user.is_authenticated:
#             # Users can see their own content + approved public content
#             return CustomerGeneratedContent.objects.filter(
#                 Q(user=self.request.user) | Q(is_approved=True)
#             )
#         else:
#             # Anonymous users can only see approved content
#             return CustomerGeneratedContent.objects.filter(is_approved=True)
    
#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)
    
#     @action(detail=True, methods=['post'])
#     def like(self, request, pk=None):
#         content = self.get_object()
#         content.likes += 1
#         content.save()
#         return Response({'likes': content.likes})
    
#     @action(detail=False, methods=['get'])
#     def my_content(self, request):
#         if not request.user.is_authenticated:
#             return Response({"error": "Authentication required"}, status=401)
        
#         user_content = CustomerGeneratedContent.objects.filter(user=request.user)
#         serializer = self.get_serializer(user_content, many=True)
#         return Response(serializer.data)
    
#     @action(detail=False, methods=['get'])
#     def featured(self, request):
#         featured_content = self.get_queryset().filter(is_featured=True, is_approved=True)
#         serializer = self.get_serializer(featured_content, many=True)
#         return Response(serializer.data)    