from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, get_user_model
from rest_framework import generics, status, permissions
from rest_framework.response import Response

from rest_framework.views import APIView
from django.http import JsonResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View

from obeeomaapp.models import Organization, Client, User 
from obeeomaapp.serializers import SignupSerializer, LoginSerializer, PasswordResetSerializer, PasswordChangeSerializer

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
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
        )
        if user:
            refresh = RefreshToken.for_user(user)
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                    "username": user.username,
                }
            )
        return Response(
            {"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
        )


class PasswordResetView(APIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        return Response({"message": f"Password reset link sent to {email}"})


class PasswordChangeView(APIView):
    serializer_class = PasswordChangeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        if not user.check_password(serializer.validated_data["old_password"]):
            return Response(
                {"error": "Old password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(serializer.validated_data["new_password"])
        user.save()
        return Response({"message": "Password updated successfully"})


#  Home View


def home(request):
    return JsonResponse(
        {
            "message": "Obeeoma API is running!",
            "endpoints": [
                "/signup/",
                "/login/",
                "/password-reset/",
                "/password-change/",
                "/swagger/",
            ],
        }
    )


# Assuming you have models for articles, appointments, and mood tracking
# from .models import Article, Appointment, MoodLog


class OverviewView(LoginRequiredMixin, View):

    # template_name = 'mental_health_app/overview.html'
    login_url = "/login/"  # Redirect here if user is not authenticated

    def get(self, request, *args, **kwargs):

        context = {
            "username": request.user.first_name or request.user.username,
            "recent_moods": recent_moods_mock,
            "upcoming_appointments": upcoming_appointments_mock,
            "recommended_articles": recommended_articles_mock,
        }

        return render(request, self.template_name, context)
