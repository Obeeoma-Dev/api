from django.urls import path
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from drf_yasg import openapi
from obeeomaapp.views import (
    SignupView, LoginView, PasswordResetView, PasswordChangeView,
    OverviewView, TrendsView, ClientEngagementView, FeaturesUsageView,
    BillingView, InviteView, UsersView, UserDetailView, ReportsView,
    CrisisInsightsView, home
)


APP_NAME = "obeeomaapp"

# --- Swagger schema view ---
SchemaView = get_schema_view(
    openapi.Info(
        title="Obeeoma API",
        default_version="v1",
        description="Endpoints for signup, login, password reset/change, and admin dashboard views",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

# --- URL patterns ---
urlpatterns = [
    # Home
    path("", home, name="home"),
    
    # Authentication
    path("auth/signup/", SignupView.as_view(), name="signup"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/reset-password/", PasswordResetView.as_view(), name="password-reset"),
    path("auth/change-password/", PasswordChangeView.as_view(), name="password-change"),
    
    # Dashboard API
    path("dashboard/overview/", OverviewView.as_view(), name="overview"),
    path("dashboard/trends/", TrendsView.as_view(), name="trends"),
    path("dashboard/client-engagement/", ClientEngagementView.as_view(), name="client-engagement"),
    path("dashboard/features-usage/", FeaturesUsageView.as_view(), name="features-usage"),
    path("dashboard/billing/", BillingView.as_view(), name="billing"),
    path("dashboard/invites/", InviteView.as_view(), name="invites"),
    path("dashboard/users/", UsersView.as_view(), name="users"),
    path("dashboard/users/<int:user_id>/", UserDetailView.as_view(), name="user-detail"),
    path("dashboard/reports/", ReportsView.as_view(), name="reports"),
    path("dashboard/crisis-insights/", CrisisInsightsView.as_view(), name="crisis-insights"),

    # API Documentation
    path("swagger/", SchemaView.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui"),
    path("redoc/", SchemaView.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
]
