from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate, get_user_model
from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from obeeomaapp.models import (
    User, Organization, Client, RecentActivity, HotlineActivity, ClientEngagement,
    AIManagement, Subscription
)
from obeeomaapp.serializers import (UserSerializer,LoginSerializer, SignupSerializer, PasswordResetSerializer, PasswordChangeSerializer,
    OrganizationSerializer, ClientSerializer, RecentActivitySerializer,
    HotlineActivitySerializer, ClientEngagementSerializer, AIManagementSerializer,
    SubscriptionSerializer
)

User = get_user_model()


# --- Permission: company admin (is_staff) ---
class IsCompanyAdmin(BasePermission):
    """
    Allows access only to users with is_staff=True.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_staff)


# --- Authentication Views ---
class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignupSerializer
    permission_classes = [permissions.AllowAny]


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
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
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        # Hook to actual email service later
        return Response({"message": f"Password reset link sent to {email}"})


class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordChangeSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        if not user.check_password(serializer.validated_data['old_password']):
            return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({"message": "Password updated successfully"})


# --- Admin Dashboard API Views (JSON) ---
class OverviewView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        org_count = Organization.objects.count()
        client_count = Client.objects.count()
        active_subscriptions = Subscription.objects.filter(is_active=True).count()

        recent = RecentActivity.objects.select_related("organization").order_by("-timestamp")[:10]
        recent_serialized = RecentActivitySerializer(recent, many=True).data

        data = {
            "organization_count": org_count,
            "client_count": client_count,
            "active_subscriptions": active_subscriptions,
            "recent_activities": recent_serialized,
        }
        return Response(data)


class TrendsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        hotline_trends = HotlineActivity.objects.select_related("organization").order_by("-recorded_at")[:20]
        data = HotlineActivitySerializer(hotline_trends, many=True).data
        return Response({"hotline_trends": data})


class ClientEngagementView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        engagements = ClientEngagement.objects.select_related("organization").order_by("-month")[:20]
        data = ClientEngagementSerializer(engagements, many=True).data
        return Response({"engagements": data})


class FeaturesUsageView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        ai_managements = AIManagement.objects.select_related("organization").order_by("-created_at")[:20]
        data = AIManagementSerializer(ai_managements, many=True).data
        return Response({"ai_managements": data})


class BillingView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        subscriptions = Subscription.objects.select_related("organization").all()
        serialized = SubscriptionSerializer(subscriptions, many=True).data
        total_revenue = sum(float(s.amount) for s in subscriptions)
        return Response({
            "subscriptions": serialized,
            "total_revenue": total_revenue
        })


class InviteView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        return Response({"message": "Invite endpoint (GET) - implement as needed"})

    def post(self, request):
        return Response({"message": "Invite created"}, status=status.HTTP_201_CREATED)


class UsersView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        clients = Client.objects.select_related("organization").all()
        data = ClientSerializer(clients, many=True).data
        return Response({"clients": data})


class UserDetailView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request, user_id):
        client = get_object_or_404(Client, id=user_id)
        data = ClientSerializer(client).data
        return Response({"client": data})


class ReportsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        reports = RecentActivity.objects.select_related("organization").order_by("-timestamp")[:50]
        data = RecentActivitySerializer(reports, many=True).data
        return Response({"reports": data})


class CrisisInsightsView(APIView):
    permission_classes = [IsCompanyAdmin]

    def get(self, request):
        hotline_data = HotlineActivity.objects.select_related("organization").order_by("-recorded_at")[:20]
        data = HotlineActivitySerializer(hotline_data, many=True).data
        return Response({"hotline_data": data})



def home(request):
    return JsonResponse({"status": "ok", "app": "obeeomaapp"})

