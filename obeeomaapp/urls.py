from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from .views import CustomTokenObtainPairView

from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
from obeeomaapp.views import (
    MentalHealthAssessmentViewSet,
    OrganizationOverviewView, EmployeeManagementView,
    DepartmentManagementView, SubscriptionManagementView,
    WellnessReportsView, OrganizationSettingsView, TestsByTypeView,
    TestsByDepartmentView, SystemAdminOverviewView, 
    OrganizationsManagementView, HotlineActivityView,
    AIManagementView, ClientEngagementView,
    ReportsAnalyticsView, SystemSettingsView, FeaturesUsageView,
    EmployerViewSet, MyBadgesView, MyStreaksView, ProgressViewSet, 
    EmailConfigCheckView, SignupView, LoginView, LogoutView, 
    PasswordResetView, PasswordResetConfirmView, PasswordChangeView,
    OverviewView, TrendsView, EmployeeEngagementView, BillingView,
    InviteView, UsersView, ReportsView, CrisisInsightsView,
       EmployeeProfileViewSet,
    AvatarProfileViewSet,
    WellnessHubViewSet,
    # MoodCheckInViewSet,           # make sure this exists in views.py
    AssessmentResultViewSet,
    # SelfHelpResourceViewSet,      # make sure this exists in views.py
    # EducationalResourceViewSet,   # make sure this exists in views.py
    CrisisTriggerViewSet,
    NotificationViewSet,
    EngagementTrackerViewSet,
    FeedbackViewSet,
    ChatSessionViewSet,
    ChatMessageViewSet,
    RecommendationLogViewSet, InvitationAcceptView, 
    InvitationVerifyView, EmployerRegistrationView, home, CustomTokenObtainPairView, InvitationAcceptView, 
    EmployerRegistrationView, home, CustomTokenObtainPairView
)



app_name = "obeeomaapp"

# --- Swagger schema view ---
schema_view = get_schema_view(
    openapi.Info(
        title="Obeeoma API",
        default_version="v1",
        description="Endpoints for authentication, assessments (GAD-7 & PHQ-9), and organization dashboards.",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

# --- Router setup ---
router = DefaultRouter()

router.register(r'mental-health/assessments', MentalHealthAssessmentViewSet, basename='mental-health-assessment')
router.register(r'employers', EmployerViewSet, basename='employer')
router.register(r'me/badges', MyBadgesView, basename='my-badges')
router.register(r'me/streaks', MyStreaksView, basename='my-streaks')
router.register(r'progress', ProgressViewSet)



# Dashboard routers (Employer Dashboard)

router.register(r'employee/profile', EmployeeProfileViewSet, basename='employee-profile')
router.register(r'employee/avatar', AvatarProfileViewSet, basename='avatar-profile')
router.register(r'employee/wellness', WellnessHubViewSet, basename='wellness-hub')
# router.register(r'employee/mood-checkin', MoodCheckInViewSet, basename='mood-checkin')
router.register(r'employee/assessments',  AssessmentResultViewSet, basename='assessment-results')
# router.register(r'resources/self-help', SelfHelpResourceViewSet, basename='self-help-resources')
# router.register(r'resources/educational', EducationalResourceViewSet, basename='educational-resources')
router.register(r'employee/crisis', CrisisTriggerViewSet, basename='crisis-trigger')
router.register(r'employee/notifications', NotificationViewSet, basename='notifications')
router.register(r'employee/engagement', EngagementTrackerViewSet, basename='engagement-tracker')
router.register(r'employee/feedback', FeedbackViewSet, basename='feedback')
router.register(r'sana/sessions', ChatSessionViewSet, basename='chat-sessions')
router.register(r'sana/messages', ChatMessageViewSet, basename='chat-messages')
router.register(r'employee/recommendations', RecommendationLogViewSet, basename='recommendation-log')

router.register(r'dashboard/organization-overview', OrganizationOverviewView, basename='organization-overview')
router.register(r'dashboard/employees', EmployeeManagementView, basename='employee-management')
router.register(r'dashboard/departments', DepartmentManagementView, basename='department-management')
router.register(r'dashboard/subscriptions', SubscriptionManagementView, basename='subscription-management')
router.register(r'dashboard/wellness-reports', WellnessReportsView, basename='wellness-reports')
router.register(r'dashboard/settings', OrganizationSettingsView, basename='organization-settings')
router.register(r'dashboard/tests-by-type', TestsByTypeView, basename='tests-by-type')
router.register(r'dashboard/tests-by-department', TestsByDepartmentView, basename='tests-by-department')

# System Admin routers
router.register(r'admin/overview', SystemAdminOverviewView, basename='system-admin-overview')
router.register(r'admin/organizations', OrganizationsManagementView, basename='organizations-management')
router.register(r'admin/hotline-activity', HotlineActivityView, basename='hotline-activity')
router.register(r'admin/ai-management', AIManagementView, basename='ai-management')
router.register(r'admin/client-engagement', ClientEngagementView, basename='client-engagement')
router.register(r'admin/reports-analytics', ReportsAnalyticsView, basename='reports-analytics')
router.register(r'admin/system-settings', SystemSettingsView, basename='system-settings')
router.register(r'admin/feature-flags', FeaturesUsageView, basename='feature-flags')

urlpatterns = [
    # Home
    path("", home, name="home"),
    
    # Debug endpoints
    path("debug/email-config/", EmailConfigCheckView.as_view(), name="email-config-check"),

    # Authentication
    path("auth/signup/", SignupView.as_view({'post': 'create'}), name="signup"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    
    # Employer Registration
    path("auth/register-organization/", EmployerRegistrationView.as_view(), name="register-organization"),
    path("auth/reset-password/", PasswordResetView.as_view({'post': 'create'}), name="password-reset"),
    path("auth/reset-password/confirm/", PasswordResetConfirmView.as_view({'post': 'create'}), name="password-reset-confirm"),
    path("auth/change-password/", PasswordChangeView.as_view({'post': 'create'}), name="password-change"),

    # Dashboard
    path("dashboard/overview/", OverviewView.as_view({'get': 'list'}), name="overview"),
    path("dashboard/trends/", TrendsView.as_view({'get': 'list'}), name="trends"),
    path("dashboard/employee-engagement/", EmployeeEngagementView.as_view({'get': 'list', 'post': 'create'}), name="employee-engagement"),
    path("dashboard/features-usage/", FeaturesUsageView.as_view({'get': 'list'}), name="features-usage"),
    path("dashboard/billing/", BillingView.as_view({'get': 'list', 'post': 'create'}), name="billing"),
    path("dashboard/invites/", InviteView.as_view({'get': 'list', 'post': 'create'}), name="employee-invitations"),
    path("dashboard/users/", UsersView.as_view({'get': 'list', 'post': 'create'}), name="users"),
    path("dashboard/reports/", ReportsView.as_view({'get': 'list'}), name="reports"),
    path("dashboard/crisis-insights/", CrisisInsightsView.as_view({'get': 'list'}), name="crisis-insights"),
    
    # Dashboard Subscription Endpoints
    path("dashboard/subscriptions/current/", SubscriptionManagementView.as_view({'get': 'current_subscription'}), name="current-subscription"),
    path("dashboard/subscriptions/plans/", SubscriptionManagementView.as_view({'get': 'available_plans'}), name="available-plans"),
    path("dashboard/subscriptions/billing-history/", SubscriptionManagementView.as_view({'get': 'billing_history'}), name="billing-history"),
    
    # System Admin Endpoints
    path("admin/organizations/growth-chart/", OrganizationsManagementView.as_view({'get': 'growth_chart'}), name="organizations-growth-chart"),
    path("admin/organizations/client-distribution/", OrganizationsManagementView.as_view({'get': 'client_distribution'}), name="organizations-client-distribution"),
    path("admin/feature-flags/by-category/", FeaturesUsageView.as_view({'get': 'by_category'}), name="feature-flags-by-category"),

 
    # Invitation acceptance (public)
    path('auth/verify-invite/', InvitationVerifyView.as_view(), name='verify-invite'),
    path('auth/accept-invite/', InvitationAcceptView.as_view({'post': 'create'}), name='accept-invite'),

    # Include router URLs
    path("", include(router.urls)),

    # JWT Authentication
    path("auth/token/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/token/verify/", TokenVerifyView.as_view(), name="token_verify"),

    # API Schema
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),

    # Swagger / Redoc
    path("swagger/", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui"),
    path("redoc/", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
]
