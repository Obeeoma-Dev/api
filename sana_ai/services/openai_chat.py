"""
openai_chat.py

This module wraps a locally hosted TinyLlama model for chatbot-style text generation.
It uses Hugging Face Transformers to load the model and tokenizer, and exposes a
single function `get_chat_response(prompt: str)` for generating responses.
"""

from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
from typing import Optional

# Load the tokenizer from the TinyLlama chat-tuned model
tokenizer = AutoTokenizer.from_pretrained(
    "TinyLlama/TinyLlama-1.1B-Chat-v1.0", trust_remote_code=True
)

# Load the model from the same checkpoint
model = AutoModelForCausalLM.from_pretrained(
    "TinyLlama/TinyLlama-1.1B-Chat-v1.0", trust_remote_code=True
)

# Create a text-generation pipeline using the model and tokenizer
chat_pipeline = pipeline(
    task="text-generation",  # Specifies the type of generation
    model=model,
    tokenizer=tokenizer,
)


def get_chat_response(prompt: str, max_tokens: Optional[int] = 200) -> str:
    """
    Generates a chatbot-style response using TinyLlama.

    Args:
        prompt (str): The user's input message.
        max_tokens (Optional[int]): Maximum number of tokens to generate.

    Returns:
        str: The model's generated response, cleaned of prompt prefix.
    """
    # Format the prompt to simulate a chat conversation
    formatted_prompt = f"User: {prompt}\nAssistant:"

    # Generate the response using the pipeline
    result = chat_pipeline(
        formatted_prompt,
        max_new_tokens=max_tokens,
        temperature=0.8,  # Controls creativity
        do_sample=True,  # Enables sampling for varied output
        top_k=50,  # Limits to top-k tokens
        top_p=0.95,  # Nucleus sampling threshold
    )

    # Extract and clean the generated text
    generated_text = result[0]["generated_text"]
    response = generated_text.replace(formatted_prompt, "").strip()

    return response
