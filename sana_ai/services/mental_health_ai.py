"""
Mental Health AI Service for Sana

This module provides dynamic AI responses focused on mental health support.
It uses OpenAI's GPT models with a specialized system prompt to ensure
responses are empathetic, professional, and mental health-focused.
"""

import os
from typing import List, Dict, Optional
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

# Try to import OpenAI
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("OpenAI package not installed. Install with: pip install openai")


class MentalHealthAI:
    """
    AI assistant specialized in mental health support.
    
    Features:
    - Dynamic responses (no static templates)
    - Mental health focused conversations
    - Context-aware (remembers conversation history)
    - Crisis detection and appropriate responses
    - Professional and empathetic tone
    """
    
    # System prompt that defines Sana's personality and boundaries
    SYSTEM_PROMPT = """You are Sana, a compassionate AI mental health support assistant. Your role is to:

1. PROVIDE SUPPORT: Offer empathetic, non-judgmental support for mental health concerns
2. ACTIVE LISTENING: Acknowledge feelings and validate emotions
3. PSYCHOEDUCATION: Share evidence-based information about mental health
4. COPING STRATEGIES: Suggest healthy coping mechanisms (breathing exercises, mindfulness, etc.)
5. RESOURCE GUIDANCE: Recommend when professional help is needed

BOUNDARIES:
- You are NOT a therapist or medical professional
- You CANNOT diagnose mental health conditions
- You CANNOT prescribe medication or treatment
- You MUST recommend professional help for serious concerns

CRISIS SITUATIONS:
If someone mentions:
- Suicidal thoughts or self-harm
- Plans to hurt themselves or others
- Severe mental health crisis

Respond with:
"I'm really concerned about what you're sharing. Please reach out to a mental health professional immediately. You can:
- Call the National Suicide Prevention Lifeline: 988
- Text 'HELLO' to 741741 (Crisis Text Line)
- Go to your nearest emergency room
- Contact your therapist or doctor

Your life matters, and there are people who want to help you right now."

CONVERSATION STYLE:
- Warm, empathetic, and supportive
- Use simple, clear language
- Ask open-ended questions to encourage sharing
- Validate feelings without judgment
- Offer hope and encouragement
- Keep responses concise (2-4 sentences usually)

TOPICS TO FOCUS ON:
- Anxiety and stress management
- Depression and mood
- Sleep and self-care
- Work-life balance
- Relationships and social support
- Mindfulness and relaxation
- Healthy habits and routines

TOPICS TO AVOID:
- Medical diagnoses
- Medication advice
- Non-mental health topics (politics, sports, etc.)
- Personal opinions on controversial topics

Remember: You're here to support, not to fix. Sometimes just listening is the most helpful thing you can do."""

    def __init__(self):
        """Initialize the AI service with OpenAI client."""
        self.client = None
        self.model = getattr(settings, 'OPENAI_MODEL', 'gpt-3.5-turbo')
        
        if OPENAI_AVAILABLE:
            api_key = getattr(settings, 'OPENAI_API_KEY', os.getenv('OPENAI_API_KEY'))
            if api_key:
                self.client = OpenAI(api_key=api_key)
            else:
                logger.warning("OpenAI API key not found in settings or environment")
    
    def is_crisis_message(self, message: str) -> bool:
        """
        Detect if a message indicates a mental health crisis.
        
        Args:
            message: User's message text
            
        Returns:
            True if crisis keywords detected
        """
        crisis_keywords = [
            'suicide', 'suicidal', 'kill myself', 'end my life', 'want to die',
            'better off dead', 'no reason to live', 'self harm', 'cut myself',
            'hurt myself', 'overdose', 'end it all', 'can\'t go on'
        ]
        
        message_lower = message.lower()
        return any(keyword in message_lower for keyword in crisis_keywords)
    
    def get_crisis_response(self) -> str:
        """
        Return immediate crisis support response.
        
        Returns:
            Crisis intervention message with resources
        """
        return """I'm really concerned about what you're sharing. Your safety is the top priority right now.

Please reach out for immediate help:
🆘 National Suicide Prevention Lifeline: 988 (call or text)
💬 Crisis Text Line: Text 'HELLO' to 741741
🏥 Emergency Services: 911
🌐 Online Chat: suicidepreventionlifeline.org/chat

You don't have to face this alone. These services are free, confidential, and available 24/7. Please reach out right now - your life matters."""
    
    def get_response(
        self,
        user_message: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        user_context: Optional[Dict] = None
    ) -> str:
        """
        Generate a dynamic AI response focused on mental health.
        
        Args:
            user_message: The user's current message
            conversation_history: Previous messages in format [{"role": "user/assistant", "content": "..."}]
            user_context: Optional context about user (recent assessments, mood, etc.)
            
        Returns:
            AI-generated response
        """
        # Check for crisis situations first
        if self.is_crisis_message(user_message):
            return self.get_crisis_response()
        
        # If OpenAI is not available, return a helpful message
        if not self.client:
            return self._get_fallback_response(user_message)
        
        try:
            # Build messages for OpenAI
            messages = [{"role": "system", "content": self.SYSTEM_PROMPT}]
            
            # Add user context if available
            if user_context:
                context_message = self._build_context_message(user_context)
                if context_message:
                    messages.append({"role": "system", "content": context_message})
            
            # Add conversation history
            if conversation_history:
                messages.extend(conversation_history[-10:])  # Last 10 messages for context
            
            # Add current user message
            messages.append({"role": "user", "content": user_message})
            
            # Get AI response
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7,  # Balanced creativity
                max_tokens=300,   # Keep responses concise
                presence_penalty=0.6,  # Encourage diverse responses
                frequency_penalty=0.3  # Reduce repetition
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"Error getting AI response: {str(e)}")
            return self._get_fallback_response(user_message)
    
    def _build_context_message(self, user_context: Dict) -> Optional[str]:
        """
        Build a context message from user data to inform AI responses.
        
        Args:
            user_context: Dictionary with user information
            
        Returns:
            Context message for the AI
        """
        context_parts = []
        
        if user_context.get('recent_assessment'):
            assessment = user_context['recent_assessment']
            context_parts.append(
                f"User recently completed a {assessment['type']} assessment "
                f"with {assessment['severity']} severity level."
            )
        
        if user_context.get('recent_mood'):
            mood = user_context['recent_mood']
            context_parts.append(f"User's recent mood: {mood}")
        
        if user_context.get('engagement_level'):
            level = user_context['engagement_level']
            context_parts.append(f"User engagement level: {level}")
        
        if context_parts:
            return "CONTEXT: " + " ".join(context_parts) + " (Use this to personalize your response, but don't explicitly mention you have this information.)"
        
        return None
    
    def _get_fallback_response(self, user_message: str) -> str:
        """
        Provide a helpful fallback response when AI is unavailable.
        
        Args:
            user_message: User's message
            
        Returns:
            Fallback response
        """
        # Simple keyword-based responses as fallback
        message_lower = user_message.lower()
        
        if any(word in message_lower for word in ['anxious', 'anxiety', 'worried', 'nervous']):
            return ("I hear that you're feeling anxious. That's a really common experience. "
                   "Have you tried any grounding techniques like deep breathing or the 5-4-3-2-1 method? "
                   "I'm here to support you through this.")
        
        elif any(word in message_lower for word in ['sad', 'depressed', 'down', 'hopeless']):
            return ("I'm sorry you're feeling this way. Your feelings are valid, and it's okay to not be okay sometimes. "
                   "Would you like to talk about what's been going on? Sometimes sharing can help lighten the load.")
        
        elif any(word in message_lower for word in ['stress', 'stressed', 'overwhelmed']):
            return ("Feeling overwhelmed is tough. Let's take this one step at a time. "
                   "What's the biggest thing on your mind right now? "
                   "Sometimes breaking things down into smaller pieces can make them feel more manageable.")
        
        elif any(word in message_lower for word in ['sleep', 'insomnia', 'tired', 'exhausted']):
            return ("Sleep issues can really affect how we feel. Good sleep hygiene can help - "
                   "like keeping a consistent schedule, avoiding screens before bed, and creating a calming bedtime routine. "
                   "How has your sleep been lately?")
        
        else:
            return ("Thank you for sharing that with me. I'm here to listen and support you. "
                   "Can you tell me more about what's on your mind? "
                   "Remember, it's okay to take your time - there's no rush.")


# Singleton instance
_ai_service = None

def get_ai_service() -> MentalHealthAI:
    """Get or create the AI service instance."""
    global _ai_service
    if _ai_service is None:
        _ai_service = MentalHealthAI()
    return _ai_service
