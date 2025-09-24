
from django.urls import path
from django.contrib import admin
from .views import SignupView, LoginView, PasswordResetView, PasswordChangeView

urlpatterns = [
    path("signup/", SignupView.as_view(), name="signup"),
    path("login/", LoginView.as_view(), name="login"),
    path("password-reset/", PasswordResetView.as_view(), name="password_reset"),
    path("password-change/", PasswordChangeView.as_view(), name="password_change"),
    
]


