# sana_ai/urls.py

from django.urls import path
from sana_ai.views import chat_view, chat_view_legacy

app_name = 'sana_ai'

urlpatterns = [
    # New authenticated endpoint with full features
    path("chat/", chat_view, name="chat"),
    
    # Legacy endpoint for backward compatibility
    path("chat/legacy/", chat_view_legacy, name="chat-legacy"),
]
