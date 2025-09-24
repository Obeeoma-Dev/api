
# dashboard/urls.py
from django.urls import path
from .views import (OverviewView, TrendsView, EngagementView, FeaturesUsageView,BillingView, InviteView, UsersView, UserDetailView,ReportsView, CrisisInsightsView,
)

urlpatterns = [
    path("admin/overview/", OverviewView.as_view(), name="admin-overview"),
    path("admin/trends/", TrendsView.as_view(), name="admin-trends"),
    path("admin/engagement/", EngagementView.as_view(), name="admin-engagement"),
    path("admin/features/", FeaturesUsageView.as_view(), name="admin-features"),
    path("admin/billing/", BillingView.as_view(), name="admin-billing"),
    path("admin/invites/", InviteView.as_view(), name="admin-invites"),
    path("admin/users/", UsersView.as_view(), name="admin-users"),
    path("admin/users/<int:user_id>/", UserDetailView.as_view(), name="admin-user-detail"),
    path("admin/reports/", ReportsView.as_view(), name="admin-reports"),
    path("admin/crisis-insights/", CrisisInsightsView.as_view(), name="admin-crisis-insights"),
]

