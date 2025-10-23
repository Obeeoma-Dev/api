# Import FastAPI to create the web API
from fastapi import FastAPI

# Import BaseModel from Pydantic to define the structure of incoming data
from pydantic import BaseModel

# Import Hugging Face tools to load the model and tokenizer
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline

import os

# Dynamically resolve the absolute path to the model folder inside sana_ai
model_path = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "tinyllama_model")
)

# Load tokenizer and model from the correct local folder
tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
model = AutoModelForCausalLM.from_pretrained(
    model_path, trust_remote_code=True, local_files_only=True
)

# Create a text-generation pipeline using the model and tokenizer
chat_pipeline = pipeline(
    "text-generation",  # Task type
    model=model,  # Loaded model
    tokenizer=tokenizer,  # Loaded tokenizer
)


# Define a function to generate chatbot responses
def get_chat_response(prompt: str) -> str:
    """
    Takes a user prompt and returns a generated response from TinyLlama.
    """
    result = chat_pipeline(
        prompt,  # The input message
        max_new_tokens=200,  # Limit response length
        temperature=0.8,  # Controls randomness (higher = more creative)
        do_sample=True,  # Enables sampling for varied output
        top_k=50,  # Limits to top 50 tokens
        top_p=0.95,  # Nucleus sampling threshold
    )
    # Remove the original prompt from the output and clean up whitespace
    return result[0]["generated_text"].replace(prompt, "").strip()


# Create a FastAPI app instance
app = FastAPI()


# Define the expected input format using Pydantic
class Prompt(BaseModel):
    message: str  # The user message to send to the chatbot


# Define an endpoint that accepts POST requests at /generate
@app.post("/generate")
async def generate_text(prompt: Prompt):
    """
    Receives a message from the user and returns a chatbot response.
    """
    response = get_chat_response(prompt.message)
    return {"response": response}  # Return the response as JSON
