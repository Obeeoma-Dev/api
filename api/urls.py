from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from django.http import JsonResponse
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

def api_root(request):
    """API root endpoint with available routes"""
    return JsonResponse({
        "message": "Welcome to Obeeoma APIs",
    })

urlpatterns = [
    path("", api_root, name="api-root"),
    path('admin/', admin.site.urls),

    
    # API v1 routes (from obeeomaapp)
    path("api/v1/", include(("obeeomaapp.urls", "obeeomaapp"), namespace="v1")),

    # Schema & Docs
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
