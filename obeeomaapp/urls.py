from django.urls import path
from .views import (
    OverviewView, TrendsView, ClientEngagementView, FeaturesUsageView,
    BillingView, InviteView, UsersView, UserDetailView,
    ReportsView, CrisisInsightsView,
    SignupView, LoginView, PasswordResetView, PasswordChangeView
)

app_name = "obeeomaapp"

urlpatterns = [
    # Dashboard / Admin URLs
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

    # Auth URLs
    path("signup/", SignupView.as_view(), name="signup"),
    path("login/", LoginView.as_view(), name="login"),
    path("password-reset/", PasswordResetView.as_view(), name="password_reset"),
    path("password-change/", PasswordChangeView.as_view(), name="password_change"),
]


