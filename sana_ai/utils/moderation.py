# Safety filters.
# chatai/utils/moderation.py


def is_safe(prompt: str) -> bool:
    """
    Checks if the prompt contains unsafe keywords.
    """
    banned_keywords = ["suicide", "kill myself", "harm", "abuse"]
    return not any(word in prompt.lower() for word in banned_keywords)
