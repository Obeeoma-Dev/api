
from django.contrib.auth import authenticate, get_user_model
from rest_framework import generics, status, permissions, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import render, redirect
from obeeomaapp.models import *
from obeeomaapp.serializers import *

User = get_user_model()

# --- Authentication Views ---

class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignupSerializer


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


class PasswordResetView(APIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        return Response({"message": f"Password reset link sent to {email}"})


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




class TermsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return render(request, "terms.html")  # show T&C page

    def post(self, request):
        # user accepts terms
        user = request.user
        user.terms_accepted = True
        user.save()
        return redirect('avatar-setup')  # go to avatar selection page

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status


class DashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.terms_accepted:
            return redirect('terms')
        if not request.user.avatar:
            return redirect('avatar-setup')
        return render(request, "dashboard.html")

# --- Custom Permission ---

class IsCompanyAdmin(IsAuthenticated):
    """Custom permission: only staff/admins allowed."""
    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.is_staff

# --- Admin Dashboard API Views ---

class OverviewView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        org_count = Organization.objects.count()
        client_count = Client.objects.count()
        active_subscriptions = Subscription.objects.filter(is_active=True).count()
        recent_activities = RecentActivity.objects.select_related("organization").order_by("-timestamp")[:10]

        return Response({
            "organization_count": org_count,
            "client_count": client_count,
            "active_subscriptions": active_subscriptions,
            "recent_activities": RecentActivitySerializer(recent_activities, many=True).data,
        })


class TrendsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        hotline_trends = HotlineActivity.objects.select_related("organization").order_by("-recorded_at")[:20]
        return Response(HotlineActivitySerializer(hotline_trends, many=True).data)


class ClientEngagementView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        engagements = ClientEngagement.objects.select_related("organization").order_by("-month")[:20]
        return Response(ClientEngagementSerializer(engagements, many=True).data)


class FeaturesUsageView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        ai_managements = AIManagement.objects.select_related("organization").order_by("-created_at")[:20]
        return Response(AIManagementSerializer(ai_managements, many=True).data)


class BillingView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        subscriptions = Subscription.objects.select_related("organization").all()
        total_revenue = sum(float(s.amount) for s in subscriptions)
        return Response({
            "subscriptions": SubscriptionSerializer(subscriptions, many=True).data,
            "total_revenue": total_revenue,
        })


# class InviteView(generics.CreateAPIView):
#     permission_classes = [IsCompanyAdmin]
#     queryset = Invite.objects.all()
#     serializer_class = InviteSerializer


class UsersView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        clients = Client.objects.select_related("organization").all()
        return Response(ClientSerializer(clients, many=True).data)


class UserDetailView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request, user_id):
        client = Client.objects.filter(id=user_id).first()
        if not client:
            return Response({"error": "Client not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(ClientSerializer(client).data)


class ReportsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        reports = RecentActivity.objects.select_related("organization").order_by("-timestamp")[:50]
        return Response(RecentActivitySerializer(reports, many=True).data)


class CrisisInsightsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        hotline_data = HotlineActivity.objects.select_related("organization").order_by("-recorded_at")[:20]
        return Response(HotlineActivitySerializer(hotline_data, many=True).data)
