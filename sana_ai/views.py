from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiParameter
import json
import logging

from sana_ai.services.mental_health_ai import get_ai_service
from obeeomaapp.models import ChatSession, ChatMessage, AssessmentResponse, MoodTracking

logger = logging.getLogger(__name__)


@extend_schema(
    tags=['Sana AI - Mental Health Chatbot'],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'message': {'type': 'string', 'description': 'User message'},
                'session_id': {'type': 'integer', 'description': 'Optional chat session ID'}
            },
            'required': ['message']
        }
    },
    responses={
        200: {
            'description': 'AI response',
            'content': {
                'application/json': {
                    'example': {
                        'response': "I hear that you're feeling anxious. That's completely valid...",
                        'session_id': 123,
                        'is_crisis': False
                    }
                }
            }
        }
    },
    description="""
    Chat with Sana, the AI mental health support assistant.
    
    Sana provides:
    - Empathetic, dynamic responses (no static templates)
    - Mental health focused conversations
    - Crisis detection and appropriate resources
    - Context-aware support based on your history
    
    The conversation is saved to your chat history for continuity.
    """
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def chat_view(request):
    """
    Dynamic AI chat endpoint for mental health support.
    
    Features:
    - Real AI responses (OpenAI GPT)
    - Mental health focused
    - Crisis detection
    - Conversation history
    - User context awareness
    """
    try:
        message = request.data.get('message', '').strip()
        session_id = request.data.get('session_id')
        
        if not message:
            return Response(
                {'error': 'Message cannot be empty'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get or create chat session
        if session_id:
            try:
                chat_session = ChatSession.objects.get(
                    id=session_id,
                    employee__user=request.user
                )
            except ChatSession.DoesNotExist:
                return Response(
                    {'error': 'Chat session not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # Create new session
            from obeeomaapp.models import EmployeeProfile
            employee_profile = EmployeeProfile.objects.filter(user=request.user).first()
            
            if not employee_profile:
                return Response(
                    {'error': 'Employee profile not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            chat_session = ChatSession.objects.create(
                employee=employee_profile,
                is_active=True
            )
        
        # Save user message
        ChatMessage.objects.create(
            session=chat_session,
            sender='user',
            message=message
        )
        
        # Get conversation history
        previous_messages = ChatMessage.objects.filter(
            session=chat_session
        ).order_by('timestamp')[:20]  # Last 20 messages
        
        conversation_history = [
            {
                'role': 'assistant' if msg.sender == 'ai' else 'user',
                'content': msg.message
            }
            for msg in previous_messages
        ]
        
        # Get user context for personalized responses
        user_context = _get_user_context(request.user)
        
        # Get AI response
        ai_service = get_ai_service()
        ai_response = ai_service.get_response(
            user_message=message,
            conversation_history=conversation_history,
            user_context=user_context
        )
        
        # Check if it's a crisis response
        is_crisis = ai_service.is_crisis_message(message)
        
        # Save AI response
        ChatMessage.objects.create(
            session=chat_session,
            sender='ai',
            message=ai_response
        )
        
        return Response({
            'response': ai_response,
            'session_id': chat_session.id,
            'is_crisis': is_crisis,
            'timestamp': ChatMessage.objects.filter(session=chat_session).last().timestamp
        })
        
    except Exception as e:
        logger.error(f"Error in chat_view: {str(e)}")
        return Response(
            {'error': 'An error occurred processing your message'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


def _get_user_context(user) -> dict:
    """
    Get user context to personalize AI responses.
    
    Args:
        user: Django user object
        
    Returns:
        Dictionary with user context
    """
    context = {}
    
    try:
        # Get recent assessment
        recent_assessment = AssessmentResponse.objects.filter(
            user=user
        ).order_by('-completed_at').first()
        
        if recent_assessment:
            context['recent_assessment'] = {
                'type': recent_assessment.assessment_type,
                'severity': recent_assessment.severity_level,
                'score': recent_assessment.total_score
            }
        
        # Get recent mood
        recent_mood = MoodTracking.objects.filter(
            user=user
        ).order_by('-checked_in_at').first()
        
        if recent_mood:
            context['recent_mood'] = recent_mood.mood
        
        # Calculate engagement level
        chat_count = ChatSession.objects.filter(employee__user=user).count()
        assessment_count = AssessmentResponse.objects.filter(user=user).count()
        
        if chat_count + assessment_count > 10:
            context['engagement_level'] = 'high'
        elif chat_count + assessment_count > 3:
            context['engagement_level'] = 'medium'
        else:
            context['engagement_level'] = 'new'
            
    except Exception as e:
        logger.warning(f"Error getting user context: {str(e)}")
    
    return context


# Legacy endpoint for backward compatibility
@csrf_exempt
def chat_view_legacy(request):
    """Legacy chat endpoint (deprecated - use /api/v1/sana/chat/ instead)"""
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Malformed JSON"}, status=400)

    prompt = data.get("message", "").strip()
    if not prompt:
        return JsonResponse({"error": "Message cannot be empty"}, status=400)

    # Use new AI service
    ai_service = get_ai_service()
    reply = ai_service.get_response(prompt)
    
    return JsonResponse({"response": reply})
