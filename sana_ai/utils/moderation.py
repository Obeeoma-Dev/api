# Safety filters.
# chatai/utils/moderation.py


"""
filters.py

Contains utility functions to validate and moderate user prompts.
"""

from typing import List

# Define keywords that indicate mental health relevance
MENTAL_HEALTH_KEYWORDS: List[str] = [
    "stress",
    "anxiety",
    "depression",
    "mental health",
    "therapy",
    "panic",
    "trauma",
    "emotions",
    "coping",
    "grief",
    "self-care",
    "mindfulness",
    "burnout",
    "wellbeing",
    "psychology",
    "support",
]


def is_mental_health_related(prompt: str) -> bool:
    """
    Checks if the prompt contains mental health-related keywords.

    Args:
        prompt (str): The user's input message.

    Returns:
        bool: True if the prompt is relevant to mental health, False otherwise.
    """
    prompt_lower = prompt.lower()
    return any(keyword in prompt_lower for keyword in MENTAL_HEALTH_KEYWORDS)
