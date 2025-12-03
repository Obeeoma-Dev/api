"""
openai_chat.py

This module wraps a locally hosted TinyLlama model for chatbot-style text generation.
It uses Hugging Face Transformers to load the model and tokenizer, and exposes a
single function `get_chat_response(prompt: str)` for generating responses.
"""

from typing import Optional

# Lazy-load heavy ML dependencies (transformers, torch) to avoid import-time
# failures when the environment doesn't have them installed. The actual model
# and tokenizer will be loaded on-demand the first time `get_chat_response`
# is called.

# Module-level caches for the tokenizer/model/pipeline
_tokenizer = None
_model = None
_chat_pipeline = None


def _ensure_model_loaded():
    """Load transformers and the TinyLlama model/tokenizer on first use.

    Raises:
        RuntimeError: if the `transformers` package (or its dependencies) is
            missing. The message contains actionable guidance for installing
            the required packages.
    """
    global _tokenizer, _model, _chat_pipeline

    if _chat_pipeline is not None:
        return

    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "The 'transformers' package is required to run the local TinyLlama "
            "model. Install it in your environment (e.g. add 'transformers', "
            "'sentencepiece' and an appropriate 'torch' wheel to requirements.txt) "
            "or switch to a hosted inference API. Original error: %s" % exc
        )

    # Load the tokenizer and model lazily
    _tokenizer = AutoTokenizer.from_pretrained(
        "TinyLlama/TinyLlama-1.1B-Chat-v1.0", trust_remote_code=True
    )

    _model = AutoModelForCausalLM.from_pretrained(
        "TinyLlama/TinyLlama-1.1B-Chat-v1.0", trust_remote_code=True
    )

    _chat_pipeline = pipeline(
        task="text-generation",
        model=_model,
        tokenizer=_tokenizer,
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
    # Ensure the model and tokenizer are available (or raise a helpful error)
    _ensure_model_loaded()

    # Format the prompt to simulate a chat conversation
    formatted_prompt = f"User: {prompt}\nAssistant:"

    # Generate the response using the pipeline
    result = _chat_pipeline(
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
