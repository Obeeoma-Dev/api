import os
from groq import Groq


# Groq ai logic.
class GroqService:
    def __init__(self):
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY environment variable is not set")
        self.client = Groq(api_key=api_key)

    def get_response(self, user_message, conversation_history):
        """
        Send conversation history + new user message to Groq model.
        """
        # Build messages list in Groq format
        messages = []
        for msg in conversation_history:
            messages.append({"role": msg["role"], "content": msg["content"]})

        # Add the latest user message
        messages.append({"role": "user", "content": user_message})

        # Call Groq
        chat_completion = self.client.chat.completions.create(
            messages=messages,
            model="llama-3.3-70b-versatile",  # free tier model
        )

        return chat_completion.choices[0].message.content

    def get_ai_response(self, user_message):
        """
        Simple method for direct AI responses without conversation history.
        """
        messages = [
            {"role": "system", "content": "You are Sana, a helpful and professional AI assistant."},
            {"role": "user", "content": user_message}
        ]
        
        chat_completion = self.client.chat.completions.create(
            messages=messages,
            model="llama-3.3-70b-versatile",
        )
        
        return chat_completion.choices[0].message.content
