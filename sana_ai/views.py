from django.shortcuts import render

# Create your views here.

# chatai/views.py

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

from sana_ai.services.openai_chat import get_chat_response
from sana_ai.utils.moderation import is_safe


@csrf_exempt
def chat_view(request):
    if request.method == "POST":
        data = json.loads(request.body)
        prompt = data.get("message", "")

        if not is_safe(prompt):
            return JsonResponse(
                {
                    "response": "I'm here to support you. Please talk to a professional or someone you trust."
                }
            )

        reply = get_chat_response(prompt)
        return JsonResponse({"response": reply})
    return JsonResponse({"error": "Invalid request method"}, status=405)
