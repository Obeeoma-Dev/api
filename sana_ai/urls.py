# chatai/urls.py

from django.urls import path
from sana_ai.views import chat_view

urlpatterns = [
    path("chat/", chat_view, name="chat"),
]
