# dashboard/views.py
from django.shortcuts import render
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
        context = {}  # later you fill with DB queries
        return render(request, "dashboard/admin_overview.html", context)


class TrendsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin_trends.html", context)


class EngagementView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin_engagement.html", context)


class FeaturesUsageView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin_features.html", context)


class BillingView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin_billing.html", context)


class InviteView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin_invites.html", context)

    def post(self, request):
        # handle form submission later
        context = {"message": "Invite sent successfully"}
        return render(request, "dashboard/admin_invites.html", context)


class UsersView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin_users.html", context)


class UserDetailView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request, user_id):
        context = {"user_id": user_id}
        return render(request, "dashboard/admin_user_detail.html", context)


class ReportsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin_reports.html", context)


class CrisisInsightsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        context = {}
        return render(request, "dashboard/admin_crisis_insights.html", context)

