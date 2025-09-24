from django.shortcuts import render, redirect
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated


class IsCompanyAdmin(IsAuthenticated):
    """Custom permission: only staff/admins allowed."""
    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.is_staff


# --- Admin Dashboard Views ---

class OverviewView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {
            "wellbeing_index": 75,
            "active_users": 120,
            "engagement_rate": "65%",
        }
        return render(request, "dashboard/admin/overview.html", context)


class TrendsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin/trends.html", context)


class EngagementView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin/engagement.html", context)


class FeaturesUsageView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin/features.html", context)


class BillingView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin/billing.html", context)


class InviteView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin/invites.html", context)

    def post(self, request):
        # Later you’ll hook into models/serializers
        # For now we simulate success + redirect
        return redirect("admin-invites")


class UsersView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin/users.html", context)


class UserDetailView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request, user_id):
        context = {"user_id": user_id}
        return render(request, "dashboard/admin/user_detail.html", context)


class ReportsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin/reports.html", context)


class CrisisInsightsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin/crisis_insights.html", context)

