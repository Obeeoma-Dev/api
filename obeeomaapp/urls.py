from django.urls import path
from django.contrib import admin
from .views import (
    OverviewView,
    TrendsView,
    EngagementView,
    FeaturesUsageView,
    BillingView,
    InviteView,
    UsersView,
    UserDetailView,
    ReportsView,
    CrisisInsightsView,
)
from .views import SignupView, LoginView, PasswordResetView, PasswordChangeView
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

#  Define schema_view BEFORE urlpatterns
schema_view = get_schema_view(
    openapi.Info(
        title="Obeeoma API",
        default_version="v1",
        description="Endpoints for signup, login, reset-password ,change-password",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

# Now reference it inside urlpatterns
urlpatterns = [
    path("signup/", SignupView.as_view(), name="signup"),
    path("login/", LoginView.as_view(), name="login"),
    path("password-reset/", PasswordResetView.as_view(), name="password_reset"),
    path("password-change/", PasswordChangeView.as_view(), name="password_change"),
    path(
        "swagger/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    path("admin/overview/", OverviewView.as_view(), name="admin-overview"),
    path("admin/trends/", TrendsView.as_view(), name="admin-trends"),
    path("admin/engagement/", EngagementView.as_view(), name="admin-engagement"),
    path("admin/features/", FeaturesUsageView.as_view(), name="admin-features"),
    path("admin/billing/", BillingView.as_view(), name="admin-billing"),
    path("admin/invites/", InviteView.as_view(), name="admin-invites"),
    path("admin/users/", UsersView.as_view(), name="admin-users"),
    path(
        "admin/users/<int:user_id>/", UserDetailView.as_view(), name="admin-user-detail"
    ),
    path("admin/reports/", ReportsView.as_view(), name="admin-reports"),
    path(
        "admin/crisis-insights/",
        CrisisInsightsView.as_view(),
        name="admin-crisis-insights",
    ),
]
