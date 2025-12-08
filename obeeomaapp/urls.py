from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework import permissions
from . import views
from .views import OrganizationViewSet, AdminUserManagementViewSet

from drf_yasg.views import get_schema_view
from drf_yasg import openapi  
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
from .views import CustomTokenObtainPairView
from obeeomaapp.views import (
     OrganizationOverviewView, EmployeeManagementView,
    DepartmentManagementView, SubscriptionManagementView,
    WellnessReportsView, OrganizationSettingsView, TestsByTypeView,
    TestsByDepartmentView, SystemAdminOverviewView,
    OrganizationsManagementView, HotlineActivityView,
    AIManagementView, ClientEngagementView,
    ReportsAnalyticsView, SystemSettingsView, FeaturesUsageView,
    MyBadgesView, MyStreaksView, ProgressViewSet,
    EmailConfigCheckView, LoginView, LogoutView,
    PasswordResetView, PasswordResetConfirmView, PasswordChangeView,
    OverviewView, TrendsView, EmployeeEngagementView, BillingView,
    UsersView, ReportsView, CrisisInsightsView,
    EmployeeProfileView, AvatarProfileView,
    MoodTrackingView, SelfHelpResourceView,
    CrisisTriggerView, NotificationView,
    EngagementTrackerView, FeedbackView, ChatSessionView,
    ChatMessageView, RecommendationLogView,
    home, OrganizationSignupView, InviteView,
    VideoViewSet, AudioViewSet, ArticleViewSet, MeditationTechniqueViewSet,
    SavedResourceViewSet, EducationalResourceViewSet, UserActivityViewSet, MediaViewSet,
     CompleteOnboardingView,
    DynamicQuestionViewSet, UserAchievementViewSet,
    AssessmentQuestionViewSet, AssessmentResponseViewSet, ActiveHotlineView,ResetPasswordCompleteView,OrganizationDetailView, CBTExerciseViewSet, SettingsViewSet,
    JournalEntryViewSet, UpdatePaymentMethodViewSet,  PSS10AssessmentViewSet,
    ContentArticleViewSet, ContentMediaViewSet, PresignUploadView, ConfirmUploadView,SignupView,VerifyPasswordResetOTPView,VerifyInvitationOTPView,
    EngagementLevelViewSet, CompanyMoodViewSet, WellnessGraphViewSet, AddEmployeeViewSet, EmployeeManagementViewSet, NotificationViewSet
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

# API routers
router.register(r'assessments/pss10', PSS10AssessmentViewSet, basename='pss10-assessment')
router.register(r'organization-signup', OrganizationSignupView, basename='organization-signup')
router.register(r'payment-methods', UpdatePaymentMethodViewSet, basename='payment-method')
# router.register(r'employee-first-login', EmployeeFirstLoginViewSet, basename='employee-first-login')
router.register(r'me/badges', MyBadgesView, basename='my-badges')
router.register(r'me/streaks', MyStreaksView, basename='my-streaks')
router.register(r'progress', ProgressViewSet)
router.register(r'cbt-exercises', CBTExerciseViewSet, basename='cbt-exercises')
router.register(r'achievements', UserAchievementViewSet, basename='achievements')
router.register(r'settings', SettingsViewSet, basename='user-settings')
# Dashboard routers (Employer Dashboard)

router.register(r'employee/profile', EmployeeProfileView, basename='employee-profile')
router.register(r'employee/avatar', AvatarProfileView, basename='avatar-profile')
router.register(r'employee/mood-tracking', MoodTrackingView, basename='mood-tracking')
router.register(r'resources/self-help', SelfHelpResourceView, basename='self-help-resources')
router.register(r'resources/educational', EducationalResourceViewSet, basename='educational-resources')
router.register(r'employee/crisis', CrisisTriggerView, basename='crisis-trigger')
router.register(r'employee/notifications', NotificationView, basename='notifications')
router.register(r'employee/engagement', EngagementTrackerView, basename='engagement-tracker')
router.register(r'employee/feedback', FeedbackView, basename='feedback')
router.register(r'sana/sessions', ChatSessionView, basename='chat-sessions')
router.register(r'sana/messages', ChatMessageView, basename='chat-messages')
router.register(r'employee/recommendations', RecommendationLogView, basename='recommendation-log')

router.register(r'dashboard/organization-overview', OrganizationOverviewView, basename='organization-overview')
router.register(r'dashboard/employees', EmployeeManagementView, basename='employee-management')
router.register(r'dashboard/departments', DepartmentManagementView, basename='department-management')
router.register(r'dashboard/subscriptions', SubscriptionManagementView, basename='subscription-management')
router.register(r'dashboard/wellness-reports', WellnessReportsView, basename='wellness-reports')
router.register(r'dashboard/settings', OrganizationSettingsView, basename='organization-settings')
router.register(r'dashboard/tests-by-type', TestsByTypeView, basename='tests-by-type')
router.register(r'dashboard/tests-by-department', TestsByDepartmentView, basename='tests-by-department')

router.register(r'videos', VideoViewSet, basename='educational-video')
router.register(r'audios', AudioViewSet, basename='calming-audio')
router.register(r'articles', ArticleViewSet, basename='mental-health-article')
router.register(r'meditations', MeditationTechniqueViewSet, basename='meditation-technique')
router.register(r'saved', SavedResourceViewSet, basename='saved-resource')
router.register(r'activity', UserActivityViewSet, basename='user-activity')

# System Admin routers
router.register(r'admin/overview', SystemAdminOverviewView, basename='system-admin-overview')
router.register(r'admin/organizations', OrganizationsManagementView, basename='organizations-management')
router.register(r'admin/hotline-activity', HotlineActivityView, basename='hotline-activity')
router.register(r'admin/ai-management', AIManagementView, basename='ai-management')
router.register(r'admin/client-engagement', ClientEngagementView, basename='client-engagement')
router.register(r'admin/reports-analytics', ReportsAnalyticsView, basename='reports-analytics')
router.register(r'admin/system-settings', SystemSettingsView, basename='system-settings')
router.register(r'admin/feature-flags', FeaturesUsageView, basename='feature-flags')
router.register(r'dynamic-questions', DynamicQuestionViewSet, basename='dynamic-question')
# ADMIN USER MANAGEMENT ROUTERS
router.register(r'admin/organizations', OrganizationViewSet, basename='admin-organizations')
router.register(r'admin/users', AdminUserManagementViewSet, basename='admin-users')
router.register(r'journal-entries', JournalEntryViewSet, basename='journal-entry')

router.register(r'dashboard/billing/verify-payment', BillingView, basename='verify-payment')

# Assessment Questionnaires (PHQ-9 & GAD-7)
router.register(r'assessments/questions', AssessmentQuestionViewSet, basename='assessment-question')
router.register(r'assessments/responses', AssessmentResponseViewSet, basename='assessment-response')

# Employee Invitations
router.register(r'invitations', InviteView, basename='invitations')

# Media uploads
router.register(r'media', MediaViewSet, basename='media')

# Content management
router.register(r'content/articles', ContentArticleViewSet, basename='content-article')
router.register(r'content/media', ContentMediaViewSet, basename='content-media')

# New endpoints
router.register(r'engagement-level', EngagementLevelViewSet, basename='engagement-level')
router.register(r'company-mood', CompanyMoodViewSet, basename='company-mood')
router.register(r'wellness-graph', WellnessGraphViewSet, basename='wellness-graph')
router.register(r'add-employee', AddEmployeeViewSet, basename='add-employee')
router.register(r'employee-management', EmployeeManagementViewSet, basename='employee-mgmt')
router.register(r'notifications', NotificationViewSet, basename='notification-list')
urlpatterns = [
    # Content management
    path("content/presign/", PresignUploadView.as_view(), name="content-presign-upload"),
    path("content/confirm-upload/", ConfirmUploadView.as_view(), name="content-confirm-upload"),
    # Home
    path("", home, name="home"),
    # Debug endpoints
    path(
        "debug/email-config/", EmailConfigCheckView.as_view(), name="email-config-check"
    ),
    # Authentication
    path("auth/signup/", SignupView.as_view({"post": "create"}), name="signup"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/reset-password/", PasswordResetView.as_view({'post': 'create'}), name="password-reset"),
    path("auth/reset-password/confirm/", PasswordResetConfirmView.as_view({'post': 'create'}), name="password-reset-confirm"),
    path("auth/change-password/", PasswordChangeView.as_view({'post': 'create'}), name="password-change"),
    path("auth/verify-password-reset-otp/", VerifyPasswordResetOTPView.as_view(), name="verify-password-reset-otp"),
    path("auth/verify-invitation-otp/", VerifyInvitationOTPView.as_view(), name="verify-invitation-otp"),
    path('auth/reset-password/complete/', ResetPasswordCompleteView.as_view({'post': 'create'}), name='password-reset-complete'),
    path('auth/mfa/setup/', views.mfa_setup, name='mfa-setup'),
    path('auth/mfa/confirm/', views.mfa_confirm, name='mfa-confirm'),
    path('auth/mfa/verify/', views.mfa_verify, name='mfa-verify'),

    # Hotline Active Endpoint
    path('auth/hotline/active/', ActiveHotlineView.as_view(), name="active-hotline"),

    # Organisation detials endpoint
    path('auth/organizations/<int:org_id>/details/', OrganizationDetailView.as_view(), name='organization-details'),

    # Complete Onboarding Endpoint
    path('auth/complete-onboarding/', CompleteOnboardingView.as_view(), name='complete-onboarding'),


  
    # # path('billing/initiate_payment/', views.initiate_subscription_payment, name='initiate-subscription-payment'),
     path('billing/verify_payment/', views.verify_payment_and_activate_subscription, name='verify-payment-activate'),

     path('billing/flutterwave-webhook/', views.flutterwave_webhook_listener, name='flutterwave-webhook'),
    
   
    # Dashboard
    path("dashboard/overview/", OverviewView.as_view({'get': 'list'}), name="overview"),
    path("dashboard/trends/", TrendsView.as_view({'get': 'list'}), name="trends"),
    path("dashboard/employee-engagement/", EmployeeEngagementView.as_view({'get': 'list', 'post': 'create'}), name="employee-engagement"),
    path("dashboard/features-usage/", FeaturesUsageView.as_view({'get': 'list'}), name="features-usage"),
    path("dashboard/billing/", BillingView.as_view({'get': 'list', 'post': 'create'}), name="billing"),
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
    path("admin/organizations/search-by-name/", OrganizationsManagementView.as_view({'get': 'search_by_name'}), name="organizations-search-by-name"),
    path("admin/feature-flags/by-category/", FeaturesUsageView.as_view({'get': 'by_category'}), name="feature-flags-by-category"),

    # Employee endpoints
    path('employee/profile/', EmployeeProfileView.as_view({'get': 'list', 'post': 'create'}), name='employee-profile'),
    path('employee/avatar/', AvatarProfileView.as_view({'get': 'list', 'post': 'create'}), name='avatar-profile'),
    path('resources/self-help/', SelfHelpResourceView.as_view({'get': 'list', 'post': 'create'}), name='self-help-resources'),

    # path('resources/educational/', EducationalResourceView.as_view({'get': 'list', 'post': 'create'}), name='educational-resources'),
    path('employee/crisis/', CrisisTriggerView.as_view({'get': 'list', 'post': 'create'}), name='crisis-trigger'),
    path('employee/notifications/', NotificationView.as_view({'get': 'list', 'post': 'create'}), name='notifications'),
    path('employee/engagement/', EngagementTrackerView.as_view({'get': 'list', 'post': 'create'}), name='engagement-tracker'),
    path('employee/feedback/', FeedbackView.as_view({'get': 'list', 'post': 'create'}), name='feedback'),
    path('sana/sessions/', ChatSessionView.as_view({'get': 'list', 'post': 'create'}), name='chat-sessions'),
    path('sana/sessions/<int:session_id>/messages/', ChatMessageView.as_view({'get': 'list', 'post': 'create'}), name='chat-messages'),
    path('employee/recommendations/', RecommendationLogView.as_view({'get': 'list', 'post': 'create'}), name='recommendation-log'),




    # Employee invitation flow (OTP-based)
    path('auth/invitation-signup/', views.InvitationAcceptView.as_view({'post': 'create'}), name='invitation-signup'),

    # Include router URLs
    path("", include(router.urls)),
    # JWT Authentication
    path("auth/token/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/token/verify/", TokenVerifyView.as_view(), name="token_verify"),
    # API Schema
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    # Swagger / Redoc
    path(
        "swagger/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    path("redoc/", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"),

    # Sana_ai.
    path("api/", include("sana_ai.urls")),
]
