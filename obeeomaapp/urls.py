from django.urls import path
from django.contrib import admin
from .views import SignupView, LoginView, PasswordResetView, PasswordChangeView, home
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from obeeomaapp.views import *

app_name = "obeeomaapp"

schema_view = get_schema_view(
    openapi.Info(
        title="Obeeoma API",
        default_version='v1',
        description="Endpoints for signup, login, password reset/change, and admin dashboard views",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

# My urls
urlpatterns = [
    # --- Admin Dashboard ---
    path("overview/", OverviewView.as_view(), name="overview"),
    path("trends/", TrendsView.as_view(), name="trends"),
    path("engagements/", ClientEngagementView.as_view(), name="engagements"),
    path("features/", FeaturesUsageView.as_view(), name="features"),
    path("billing/", BillingView.as_view(), name="billing"),
    path("invites/", InviteView.as_view(), name="admin-invites"),
    path("users/", UsersView.as_view(), name="users"),
    path("users/<int:user_id>/", UserDetailView.as_view(), name="user-detail"),
    path("reports/", ReportsView.as_view(), name="reports"),
    path("crisis-insights/", CrisisInsightsView.as_view(), name="crisis-insights"),


    path("", home, name="home"),   # root URL
    path("signup/", SignupView.as_view(), name="signup"),
    path("login/", LoginView.as_view(), name="login"),
    path("password-reset/", PasswordResetView.as_view(), name="password_reset"),
    path("password-change/", PasswordChangeView.as_view(), name="password_change"),

    # --- Swagger Docs ---
    path("swagger/", schema_view.with_ui('swagger', cache_timeout=0), name="schema-swagger-ui"),
]
