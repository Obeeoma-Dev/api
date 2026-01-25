# permissions.py
from rest_framework import permissions

class IsSystemAdmin(permissions.BasePermission):
    """
    Grant access only to system_admin role or Django superuser.
    """
    def has_permission(self, request, view):
        return (
            request.user and request.user.is_authenticated and
            (request.user.is_superuser or request.user.role == 'system_admin')
        )
from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsAdminOrReadOnly(BasePermission):
    """
    Allow anyone to read data (GET, HEAD, OPTIONS),
    but only admins can modify data (POST, PUT, PATCH, DELETE).
    """

    def has_permission(self, request, view):
        # SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')
        if request.method in SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_staff)

# permissions for system admin to upload media files.
# Last updated: 2025-01-25 - Deployment restart trigger v2
class IsSystemAdminOrReadOnly(permissions.BasePermission):
    """
    Allow read-only to any authenticated user (or even AllowAny if public).
    Only system admins can create/update/delete.
    Special superuser gideonmuteso@gmail.com has full access without restrictions.
    """

    def has_permission(self, request, view):
        # Special superuser bypass - full access without restrictions
        if (
            request.user and 
            request.user.is_authenticated and 
            request.user.email == "gideonmuteso@gmail.com"
        ):
            return True
        
        # Everyone can list/retrieve (if desired). If you want anonymous access, return True here for SAFE_METHODS
        if request.method in permissions.SAFE_METHODS:
            return True

        # For modifying methods, require authenticated + system admin
        if not request.user or not request.user.is_authenticated:
            return False

        # Adjust check to your user model: here we check a custom attribute `is_system_admin`.
        # You can change to request.user.is_staff or group membership.
        return getattr(request.user, 'is_system_admin', False) or request.user.is_staff or request.user.is_superuser