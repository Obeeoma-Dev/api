from django.urls import path
from .views import (
    OverviewView,
    TrendsView,
    ClientEngagementView,
    FeaturesUsageView,
    BillingView,
    InviteView,
    UsersView,
    UserDetailView,
    ReportsView,
    CrisisInsightsView,
)

app_name = "obeeomaapp"

urlpatterns = [
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
]

