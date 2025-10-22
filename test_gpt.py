# test_gpt.py

from sana_ai.services.openai_chat import get_chat_response

if __name__ == "__main__":
    prompt = "What is emotional resilience?"
    reply = get_chat_response(prompt)
    print("AI Response:", reply)