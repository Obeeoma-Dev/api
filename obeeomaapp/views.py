from django.shortcuts import render, redirect
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from .models import (
    Organization, Client, AIRecommendation,
    HotlineActivity, ClientEngagement, Subscription,
    RecentActivity
)


class IsCompanyAdmin(IsAuthenticated):
    """Custom permission: only staff/admins allowed."""
    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.is_staff


# --- Admin Dashboard Views ---

class OverviewView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        org_count = Organization.objects.count()
        client_count = Client.objects.count()
        active_subscriptions = Subscription.objects.filter(is_active=True).count()

        context = {
            "organization_count": org_count,
            "client_count": client_count,
            "active_subscriptions": active_subscriptions,
            "recent_activities": RecentActivity.objects.select_related("organization").all()[:10],
        }
        return render(request, "dashboard/admin/overview.html", context)


class TrendsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        hotline_trends = HotlineActivity.objects.select_related("organization").order_by("-recorded_at")[:20]
        ai_recommendations = AIRecommendation.objects.select_related("organization").order_by("-created_at")[:10]

        context = {
            "hotline_trends": hotline_trends,
            "ai_recommendations": ai_recommendations,
        }
        return render(request, "dashboard/admin/trends.html", context)


class EngagementView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        engagements = ClientEngagement.objects.select_related("organization").order_by("-month")[:20]

        context = {
            "engagements": engagements,
        }
        return render(request, "dashboard/admin/engagement.html", context)


class FeaturesUsageView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        recommendations = AIRecommendation.objects.select_related("organization").order_by("-created_at")[:20]

        context = {
            "recommendations": recommendations,
        }
        return render(request, "dashboard/admin/features.html", context)


class BillingView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        subscriptions = Subscription.objects.select_related("organization").all()
        total_revenue = sum(s.revenue for s in subscriptions)

        context = {
            "subscriptions": subscriptions,
            "total_revenue": total_revenue,
        }
        return render(request, "dashboard/admin/billing.html", context)


class InviteView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        return render(request, "dashboard/admin/invites.html")

    def post(self, request):
        # Later hook into Client/Organization logic
        return redirect("admin-invites")


class UsersView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        clients = Client.objects.select_related("organization").all()

        context = {
            "clients": clients,
        }
        return render(request, "dashboard/admin/users.html", context)


class UserDetailView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request, user_id):
        client = Client.objects.filter(id=user_id).first()

        context = {
            "client": client,
        }
        return render(request, "dashboard/admin/user_detail.html", context)


class ReportsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        reports = RecentActivity.objects.select_related("organization").order_by("-timestamp")[:50]

        context = {
            "reports": reports,
        }
        return render(request, "dashboard/admin/reports.html", context)


class CrisisInsightsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        hotline_data = HotlineActivity.objects.select_related("organization").order_by("-recorded_at")[:20]

        context = {
            "hotline_data": hotline_data,
        }
        return render(request, "dashboard/admin/crisis_insights.html", context)
