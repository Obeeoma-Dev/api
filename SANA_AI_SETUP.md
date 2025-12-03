# 🤖 Sana AI - Dynamic Mental Health Chatbot Setup

## Overview

Sana is now a **fully dynamic AI chatbot** that:
- ✅ Uses real AI (OpenAI GPT) - NO static responses
- ✅ Focuses ONLY on mental health topics
- ✅ Remembers conversation history
- ✅ Detects crisis situations
- ✅ Personalizes responses based on user context
- ✅ Professional and empathetic

---

## 🚀 Quick Setup

### 1. Install OpenAI Package

```bash
pip install openai
```

### 2. Get OpenAI API Key

1. Go to https://platform.openai.com/api-keys
2. Create an account or sign in
3. Click "Create new secret key"
4. Copy the key (starts with `sk-...`)

### 3. Add API Key to Settings

**Option A: Environment Variable (Recommended)**
```bash
# .env file
OPENAI_API_KEY=sk-your-api-key-here
OPENAI_MODEL=gpt-3.5-turbo  # or gpt-4 for better responses
```

**Option B: Django Settings**
```python
# api/settings.py
OPENAI_API_KEY = 'sk-your-api-key-here'
OPENAI_MODEL = 'gpt-3.5-turbo'  # or 'gpt-4'
```

### 4. Update Requirements

```bash
# requirements.txt
openai>=1.0.0
```

---

## 📱 API Usage

### Endpoint
```
POST /api/v1/sana/chat/
```

### Headers
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

### Request Body
```json
{
  "message": "I've been feeling really anxious lately",
  "session_id": 123  // Optional - omit to start new session
}
```

### Response
```json
{
  "response": "I hear that you're feeling anxious, and I want you to know that's a really common experience. Anxiety can feel overwhelming, but there are ways to manage it. Have you noticed any particular triggers or patterns? Sometimes identifying what brings on the anxiety can help us find ways to cope with it.",
  "session_id": 123,
  "is_crisis": false,
  "timestamp": "2025-11-15T10:30:00Z"
}
```

---

## 🎯 Features

### 1. Dynamic Responses (No Static Templates!)

**Old Way (Static):**
```python
if "anxious" in message:
    return "Try deep breathing"  # Same response every time
```

**New Way (Dynamic AI):**
```python
# AI generates unique, contextual responses every time
response = ai_service.get_response(message, history, context)
# Different response each time, personalized to the conversation
```

### 2. Mental Health Focus

Sana is programmed to ONLY discuss mental health topics:
- ✅ Anxiety, depression, stress
- ✅ Sleep, self-care, mindfulness
- ✅ Coping strategies
- ✅ Emotional support
- ❌ Politics, sports, general chat
- ❌ Medical diagnoses
- ❌ Medication advice

### 3. Crisis Detection

Automatically detects crisis keywords:
```python
crisis_keywords = [
    'suicide', 'suicidal', 'kill myself', 
    'self harm', 'want to die', etc.
]
```

**Crisis Response:**
```
I'm really concerned about what you're sharing. Your safety is the top priority.

Please reach out for immediate help:
🆘 National Suicide Prevention Lifeline: 988
💬 Crisis Text Line: Text 'HELLO' to 741741
🏥 Emergency Services: 911
```

### 4. Conversation History

Sana remembers the conversation:
```python
# Conversation flow
User: "I'm feeling anxious"
Sana: "I hear that you're feeling anxious..."

User: "It's been going on for weeks"
Sana: "I understand this has been ongoing for you. That must be exhausting..."
# ↑ Remembers previous context
```

### 5. User Context Awareness

Sana knows about the user's:
- Recent assessment results (PHQ-9, GAD-7)
- Recent mood tracking
- Engagement level

```python
# If user scored high on PHQ-9
Sana: "I know things have been tough lately. How are you feeling today?"

# If user is new
Sana: "Welcome! I'm Sana, and I'm here to support you..."
```

---

## 💡 Example Conversations

### Example 1: Anxiety Support
```
User: "I can't stop worrying about work"

Sana: "It sounds like work stress is really weighing on you. That constant 
worry can be exhausting. Have you been able to identify what specifically 
about work is causing the most anxiety? Sometimes breaking it down can help 
us find ways to manage it."

User: "I'm worried I'm not good enough"

Sana: "Those feelings of self-doubt can be really painful. I want you to 
know that many people struggle with these thoughts, especially when under 
stress. What would you say to a friend who told you they felt this way? 
Sometimes we're much kinder to others than we are to ourselves."
```

### Example 2: Sleep Issues
```
User: "I can't sleep at night"

Sana: "Sleep difficulties can really affect how we feel during the day. 
How long has this been going on? And what does your bedtime routine 
typically look like?"

User: "About 2 weeks. I just scroll on my phone"

Sana: "I appreciate you sharing that. Screen time before bed can definitely 
interfere with sleep - the blue light affects our natural sleep hormones. 
Would you be open to trying some sleep hygiene techniques? Things like 
putting the phone away an hour before bed, keeping the room cool and dark, 
or trying some gentle stretching or breathing exercises?"
```

### Example 3: Crisis Detection
```
User: "I don't want to be here anymore"

Sana: "I'm really concerned about what you're sharing. Your safety is the 
top priority right now.

Please reach out for immediate help:
🆘 National Suicide Prevention Lifeline: 988 (call or text)
💬 Crisis Text Line: Text 'HELLO' to 741741
🏥 Emergency Services: 911

You don't have to face this alone. These services are free, confidential, 
and available 24/7. Please reach out right now - your life matters."
```

---

## 🔧 Configuration Options

### Model Selection

**GPT-3.5-turbo (Recommended for most cases)**
- Fast responses
- Cost-effective
- Good quality
- ~$0.002 per 1K tokens

```python
OPENAI_MODEL = 'gpt-3.5-turbo'
```

**GPT-4 (Premium option)**
- Best quality responses
- More empathetic
- Better context understanding
- ~$0.03 per 1K tokens

```python
OPENAI_MODEL = 'gpt-4'
```

### Response Parameters

In `sana_ai/services/mental_health_ai.py`:

```python
response = self.client.chat.completions.create(
    model=self.model,
    messages=messages,
    temperature=0.7,      # 0.0-1.0: Lower = more focused, Higher = more creative
    max_tokens=300,       # Maximum response length
    presence_penalty=0.6, # Encourage diverse topics
    frequency_penalty=0.3 # Reduce repetition
)
```

---

## 🧪 Testing

### Test 1: Basic Chat
```bash
curl -X POST http://localhost:8000/api/v1/sana/chat/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "I feel anxious"}'
```

### Test 2: Crisis Detection
```bash
curl -X POST http://localhost:8000/api/v1/sana/chat/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "I want to hurt myself"}'
```

### Test 3: Conversation History
```bash
# First message
curl -X POST http://localhost:8000/api/v1/sana/chat/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "I feel sad"}'

# Response includes session_id: 123

# Second message (with session_id)
curl -X POST http://localhost:8000/api/v1/sana/chat/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "It has been going on for weeks", "session_id": 123}'
```

---

## 💰 Cost Estimation

### GPT-3.5-turbo Pricing
- Input: $0.0015 per 1K tokens
- Output: $0.002 per 1K tokens

**Average conversation:**
- User message: ~50 tokens
- AI response: ~150 tokens
- System prompt: ~500 tokens (first message only)
- Cost per message: ~$0.0003 (less than a cent!)

**Monthly estimate (1000 employees, 10 messages each):**
- Total messages: 10,000
- Total cost: ~$3-5 per month

### GPT-4 Pricing
- Input: $0.03 per 1K tokens
- Output: $0.06 per 1K tokens
- ~10x more expensive but higher quality

---

## 🔒 Security & Privacy

### Data Storage
- ✅ Conversations stored in your database
- ✅ Linked to employee accounts
- ✅ Employer cannot see individual chats (privacy)
- ✅ Only aggregated usage metrics visible to employer

### OpenAI Privacy
- ✅ API calls are NOT used to train OpenAI models
- ✅ Data is not retained by OpenAI (as of March 2023)
- ✅ Encrypted in transit (HTTPS)

### Best Practices
```python
# settings.py
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')  # Use environment variables
# Never commit API keys to git!
```

---

## 🚨 Fallback Mode

If OpenAI is unavailable (no API key, network issues, etc.), Sana automatically falls back to basic keyword-based responses:

```python
# Fallback responses (when AI unavailable)
if 'anxious' in message:
    return "I hear that you're feeling anxious. Have you tried deep breathing?"

# But with AI (dynamic):
return "I understand you're feeling anxious. That's really tough. Can you 
tell me more about what's been triggering these feelings? Sometimes talking 
through it can help us find ways to cope."
```

---

## 📊 Monitoring

### Check AI Usage
```python
# In Django shell
from obeeomaapp.models import ChatMessage

# Total AI messages
ChatMessage.objects.filter(sender='ai').count()

# Messages today
from django.utils import timezone
from datetime import timedelta

today = timezone.now().date()
ChatMessage.objects.filter(
    sender='ai',
    timestamp__date=today
).count()
```

### Check Costs
```python
# Rough estimate
total_messages = ChatMessage.objects.filter(sender='ai').count()
estimated_cost = total_messages * 0.0003  # $0.0003 per message
print(f"Estimated cost: ${estimated_cost:.2f}")
```

---

## 🎓 Customization

### Modify Sana's Personality

Edit `sana_ai/services/mental_health_ai.py`:

```python
SYSTEM_PROMPT = """You are Sana, a compassionate AI...

CONVERSATION STYLE:
- Warm, empathetic, and supportive  # ← Customize here
- Use simple, clear language
- Keep responses concise (2-4 sentences)
...
"""
```

### Add More Crisis Keywords

```python
crisis_keywords = [
    'suicide', 'suicidal', 'kill myself',
    # Add your own:
    'overdose', 'jump off', 'end it all'
]
```

### Adjust Response Length

```python
response = self.client.chat.completions.create(
    ...
    max_tokens=300,  # ← Change this (100-500 recommended)
)
```

---

## ✅ Summary

**What Changed:**
- ❌ Old: Static, template-based responses
- ✅ New: Dynamic AI with OpenAI GPT

**Benefits:**
- More natural conversations
- Context-aware responses
- Better crisis detection
- Personalized support
- Remembers conversation history

**Setup:**
1. Install: `pip install openai`
2. Get API key from OpenAI
3. Add to settings: `OPENAI_API_KEY=sk-...`
4. Done! Sana is now fully dynamic

**Cost:**
- ~$0.0003 per message
- ~$3-5 per month for 1000 employees

**Next Steps:**
1. Get OpenAI API key
2. Test with mobile/web app
3. Monitor usage and costs
4. Customize Sana's personality if needed
