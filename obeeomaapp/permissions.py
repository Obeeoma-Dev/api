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
