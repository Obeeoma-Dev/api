from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

from sana_ai.services.openai_chat import get_chat_response


# Basic moderation logic
def is_safe(text: str) -> bool:
    """
    Checks if the input text contains unsafe keywords.
    Extend this with ML or external moderation APIs as needed.
    """
    unsafe_keywords = ["suicide", "kill myself", "harm", "abuse", "die", "worthless"]
    lowered = text.lower()
    return not any(keyword in lowered for keyword in unsafe_keywords)


@csrf_exempt
def chat_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Malformed JSON"}, status=400)

    prompt = data.get("message", "").strip()
    if not prompt:
        return JsonResponse({"error": "Message cannot be empty"}, status=400)

    if not is_safe(prompt):
        return JsonResponse({
            "response": "I'm here to support you. Please talk to a professional or someone you trust."
        })

    reply = get_chat_response(prompt)
    return JsonResponse({"response": reply})
