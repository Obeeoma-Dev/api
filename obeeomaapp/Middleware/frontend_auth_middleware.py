from django.http import JsonResponse
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
import json

class FrontendAuthMiddleware:
    """
    Middleware to validate frontend authentication for SPA routes
    This acts as a server-side backup for browser navigation security
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_auth = JWTAuthentication()
        
        # Routes that require authentication
        self.protected_routes = [
            '/system-admin',
            '/employer-dashboard', 
            '/employee-dashboard'
        ]
        
        # API routes (skip these)
        self.api_routes = ['/api/', '/admin/', '/static/', '/media/']

    def __call__(self, request):
        path = request.path
        
        # Skip API routes and static files
        if any(path.startswith(route) for route in self.api_routes):
            return self.get_response(request)
        
        # Check if this is a protected frontend route
        if any(path.startswith(route) for route in self.protected_routes):
            # Check for Authorization header
            auth_header = request.headers.get('Authorization')
            
            if not auth_header:
                # No token provided - check if user is authenticated via session
                if not request.user.is_authenticated:
                    return self._unauthorized_response()
                else:
                    # User is authenticated via session, allow access
                    return self.get_response(request)
            
            # Validate JWT token
            try:
                # Remove 'Bearer ' prefix if present
                token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else auth_header
                
                # Validate token
                validated_token = self.jwt_auth.get_validated_token(token)
                user = self.jwt_auth.get_user(validated_token)
                
                if not user.is_authenticated:
                    return self._unauthorized_response()
                    
            except (InvalidToken, Exception) as e:
                # Token is invalid
                return self._unauthorized_response()
        
        # For non-protected routes or valid authentication, continue normally
        return self.get_response(request)
    
    def _unauthorized_response(self):
        """Return unauthorized response that redirects to login"""
        return JsonResponse({
            'error': 'Authentication required',
            'redirect': '/login',
            'message': 'Please login to access this page'
        }, status=401)
