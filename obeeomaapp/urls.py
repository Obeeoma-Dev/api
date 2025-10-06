from django.urls import path, include
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from drf_yasg import openapi
from rest_framework.routers import DefaultRouter
from obeeomaapp.views import (
    SignupView, LoginView, PasswordResetView, PasswordChangeView,
    OverviewView, TrendsView, ClientEngagementView, FeaturesUsageView,
    BillingView, InviteView, UsersView, ReportsView,
    CrisisInsightsView, home, EmployeeProfileView, AvatarProfileView,
    WellnessHubView, MoodCheckInView, AssessmentResultView,
    SelfHelpResourceView, EducationalResourceView, CrisisTriggerView,
    NotificationView, EngagementTrackerView, FeedbackView,
    ChatSessionView, ChatMessageView, RecommendationLogView,
    MentalHealthAssessmentViewSet
)

app_name = "obeeomaapp"

# --- Swagger schema view ---
SchemaView = get_schema_view(
    openapi.Info(
        title="Obeeoma API",
        default_version="v1",
        description="Endpoints for signup, login, password reset/change, admin dashboard views, and mental health assessments (GAD-7 & PHQ-9)",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

# Create router for ViewSets
router = DefaultRouter()
router.register(r'mental-health/assessments', MentalHealthAssessmentViewSet, basename='mental-health-assessment')

# --- URL patterns ---
urlpatterns = [
    # Home
    path("", home, name="home"),
    
    # Authentication
    path("auth/signup/", SignupView.as_view({'post': 'create'}), name="signup"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/reset-password/", PasswordResetView.as_view({'post': 'create'}), name="password-reset"),
    path("auth/change-password/", PasswordChangeView.as_view({'post': 'create'}), name="password-change"),
    
    # Dashboard API
    path("dashboard/overview/", OverviewView.as_view({'get': 'list'}), name="overview"),
    path("dashboard/trends/", TrendsView.as_view({'get': 'list'}), name="trends"),
    path("dashboard/client-engagement/", ClientEngagementView.as_view({'get': 'list', 'post': 'create'}), name="client-engagement"),
    path("dashboard/features-usage/", FeaturesUsageView.as_view({'get': 'list', 'post': 'create'}), name="features-usage"),
    path("dashboard/billing/", BillingView.as_view({'get': 'list', 'post': 'create'}), name="billing"),
    path("dashboard/invites/", InviteView.as_view({'get': 'list', 'post': 'create'}), name="invites"),
    path("dashboard/users/", UsersView.as_view({'get': 'list', 'post': 'create'}), name="users"),
    path("dashboard/reports/", ReportsView.as_view({'get': 'list'}), name="reports"),
    path("dashboard/crisis-insights/", CrisisInsightsView.as_view({'get': 'list'}), name="crisis-insights"),

    # Employee Management
    # Employee Profile & Avatar
    path('employee/profile/', EmployeeProfileView.as_view({'get': 'list', 'post': 'create'}), name='employee-profile'),
    path('employee/avatar/', AvatarProfileView.as_view({'get': 'list', 'post': 'create'}), name='avatar-profile'),

    # Wellness & Mood
    path('employee/wellness/', WellnessHubView.as_view({'get': 'list', 'post': 'create'}), name='wellness-hub'),
    path('employee/mood-checkin/', MoodCheckInView.as_view({'get': 'list', 'post': 'create'}), name='mood-checkin'),

    # Assessments
    path('employee/assessments/', AssessmentResultView.as_view({'get': 'list', 'post': 'create'}), name='assessment-results'),

    # Resources
    path('resources/self-help/', SelfHelpResourceView.as_view({'get': 'list', 'post': 'create'}), name='self-help-resources'),
    path('resources/educational/', EducationalResourceView.as_view({'get': 'list', 'post': 'create'}), name='educational-resources'),

    # Crisis & Notifications
    path('employee/crisis/', CrisisTriggerView.as_view({'get': 'list', 'post': 'create'}), name='crisis-trigger'),
    path('employee/notifications/', NotificationView.as_view({'get': 'list', 'post': 'create'}), name='notifications'),

    # Engagement & Feedback
    path('employee/engagement/', EngagementTrackerView.as_view({'get': 'list', 'post': 'create'}), name='engagement-tracker'),
    path('employee/feedback/', FeedbackView.as_view({'get': 'list', 'post': 'create'}), name='feedback'),

    # Sana Chat
    path('sana/sessions/', ChatSessionView.as_view({'get': 'list', 'post': 'create'}), name='chat-sessions'),
    path('sana/sessions/<int:session_id>/messages/', ChatMessageView.as_view({'get': 'list', 'post': 'create'}), name='chat-messages'),

    # Recommendations
    path('employee/recommendations/', RecommendationLogView.as_view({'get': 'list', 'post': 'create'}), name='recommendation-log'),

    # Include router URLs for mental health assessments
    path('', include(router.urls)),

    # API Documentation
    path("swagger/", SchemaView.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui"),
    path("redoc/", SchemaView.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
]

