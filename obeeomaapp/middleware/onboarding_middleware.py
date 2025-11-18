# # ONBOARDING 
# from django.http import JsonResponse
# from django.urls import resolve

# # Routes that do NOT require onboarding to be completed
# ALLOWED_URLS = [
#     # Invitation flow (first-time user)
#         "verify-invite",
#         "accept-invite",
#         "signup",                       # They create account after invitation
#         "complete-onboarding", 
#         "organization-signup",                
#         'docs',
#         'schema',
#         'swagger',
#         'swagger-ui',
#         'redoc',
    
# ]

# class EnsureOnboardingCompleteMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         user = request.user

#         #  If the user is NOT authenticated → allow request (login/signup will handle it)
#         if not user.is_authenticated:
#             return self.get_response(request)

#         #  Try to get the name of the URL being accessed
#         try:
#             url_name = resolve(request.path).url_name
#         except:
#             return self.get_response(request)

#         #  If the URL is in allowed list → let it pass
#         if url_name in ALLOWED_URLS:
#             return self.get_response(request)

#         #  If user has NOT completed onboarding → block all protected endpoints
#         if not user.onboarding_completed:
#             return JsonResponse({
#                 "detail": "Onboarding incomplete. Please complete onboarding.",
#                 "onboarding_required": True,
#                 "redirect_to": "/onboarding/"
#             }, status=403)

#         #  Allow the request normally if onboarding is done
#         return self.get_response(request)
