"""
main.py

Sets up a FastAPI server with a /generate endpoint for mental health chatbot responses.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.concurrency import run_in_threadpool

# Import your chatbot logic
from sana_ai.services.openai_chat import get_chat_response

# Import your moderation filter
from sana_ai.utils.moderation import is_mental_health_related

app = FastAPI()


class Prompt(BaseModel):
    message: str


@app.post("/generate")
async def generate_text(prompt: Prompt) -> dict[str, str]:
    """
    Validates the prompt and returns a mental health-focused response.
    """
    # Check if the prompt is relevant to mental health
    if not is_mental_health_related(prompt.message):
        return {
            "response": "I'm here to support mental health topics. Could you rephrase your question?"
        }

    # Format the prompt to guide the model toward mental health advice
    formatted_prompt = (
        f"User: {prompt.message} (Please answer as a mental health advisor)\nAssistant:"
    )

    # Run the model in a thread to avoid blocking
    response = await run_in_threadpool(lambda: get_chat_response(formatted_prompt))

    return {"response": response}
