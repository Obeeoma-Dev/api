from django.urls import path
from django.contrib import admin
from .views import SignupView, LoginView, PasswordResetView, PasswordChangeView, home
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

#  Define schema_view BEFORE urlpatterns
schema_view = get_schema_view(
   openapi.Info(
      title="Obeeoma API",
      default_version='v1',
      description="Authentication endpoints for user signup, login, password reset, and password change.",

   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

# My urls
urlpatterns = [
    path("", home, name="home"),   # root URL
    path("api/signup/", SignupView.as_view(), name="signup"),
    path("api/login/", LoginView.as_view(), name="login"),
    path("api/password-reset/", PasswordResetView.as_view(), name="password_reset"),
    path("api/password-change/", PasswordChangeView.as_view(), name="password_change"),
    path('api/swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
     
]


