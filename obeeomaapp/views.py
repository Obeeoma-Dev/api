from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render, redirect
from obeeomaapp.serializers import (
    SignupSerializer,
    LoginSerializer,
    PasswordResetSerializer,
    PasswordChangeSerializer

)
from obeeomaapp.models import (
    Organization,
    Client,
    HotlineActivity,
    ClientEngagement,
    Subscription,
    RecentActivity,
    AIManagement 

)

User = get_user_model()

#  Signup
class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignupSerializer


#  Login
class LoginView(APIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password']
        )
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "username": user.username,
            })
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


#  Password Reset (stub – email integration later)
class PasswordResetView(APIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        return Response({"message": f"Password reset link sent to {email}"})


#  Password Change
class PasswordChangeView(APIView):
    serializer_class = PasswordChangeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        if not user.check_password(serializer.validated_data['old_password']):
            return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({"message": "Password updated successfully"})

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
            "recent_activities": RecentActivity.objects.select_related(
                "organization"
            ).all()[:10],
        }
        return render(request, "overview.html", context)


class TrendsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        hotline_trends = HotlineActivity.objects.select_related(
            "organization"
        ).order_by("-recorded_at")[:20]

        context = {
            "hotline_trends": hotline_trends,
        }
        return render(request, "trends.html", context)


class ClientEngagementView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        engagements = ClientEngagement.objects.select_related("organization").order_by(
            "-month"
        )[:20]

        context = {
            "engagements": engagements,
        }
        return render(request, "engagement.html", context)


class FeaturesUsageView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        ai_managements = AIManagement.objects.select_related(
            "organization"
        ).order_by("-created_at")[:20]

        context = {
            "ai_managements": ai_managements,
        }
        return render(request, "features.html", context)


class BillingView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        subscriptions = Subscription.objects.select_related("organization").all()
        total_revenue = sum(float(s.Subscriptions) for s in subscriptions)

        context = {
            "subscriptions": subscriptions,
            "total_revenue": total_revenue,
        }
        return render(request, "billing.html", context)


class InviteView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        return render(request, "invites.html")

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
        return render(request, "users.html", context)


class UserDetailView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request, user_id):
        client = Client.objects.filter(id=user_id).first()

        context = {
            "client": client,
        }
        return render(request, "user_detail.html", context)


class ReportsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        reports = RecentActivity.objects.select_related("organization").order_by(
            "-timestamp"
        )[:50]

        context = {
            "reports": reports,
        }
        return render(request, "reports.html", context)


class CrisisInsightsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        hotline_data = HotlineActivity.objects.select_related("organization").order_by(
            "-recorded_at"
        )[:20]

        context = {
            "hotline_data": hotline_data,
        }
        return render(request, "crisis_insights.html", context)
