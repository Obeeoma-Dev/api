# Groq AI Integration Documentation

## Location of Groq Service

**Service File:** `obeeomaapp/Services/groq_service.py`

```python
class GroqService:
    def __init__(self):
        self.client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    
    def get_response(self, user_message, conversation_history):
        # Calls Groq API with llama-3.3-70b-versatile model
```

---

## Where Groq is Used

### 1. **ChatMessageView** (`obeeomaapp/views.py` - Line 1859)
   - **Purpose:** Handles AI chat messages
   - **Flow:**
     1. User sends a message
     2. System builds conversation history
     3. Calls `GroqService.get_response()`
     4. Saves AI reply to database

### 2. **Environment Variable Required**
   - `GROQ_API_KEY` - Must be set in your `.env` file

---



### Chat Message Endpoints (Missing)
```
GET    /api/v1/sana/sessions/{session_id}/messages/  - List messages in session
POST   /api/v1/sana/sessions/{session_id}/messages/   - Send message (triggers Groq)
GET    /api/v1/sana/sessions/{session_id}/messages/{id}/ - Get specific message
PUT    /api/v1/sana/sessions/{session_id}/messages/{id}/ - Update message
DELETE /api/v1/sana/sessions/{session_id}/messages/{id}/ - Delete message
```

---


# AI Chat endpoints (Groq-powered)
router.register(r'sana/sessions', ChatSessionView, basename='chat-session')
router.register(r'sana/sessions/(?P<session_id>\d+)/messages', ChatMessageView, basename='chat-message')
```

**Note:** The nested route for messages requires a custom router setup. See the fix below.

---

## How Groq API Works

### 1. **API Call Flow:**
```
User Message → ChatMessageView.perform_create()
    ↓
Build conversation history from database
    ↓
GroqService.get_response(user_message, conversation_history)
    ↓
Groq API Call (llama-3.3-70b-versatile)
    ↓
AI Response saved to ChatMessage
```

### 2. **Groq API Parameters:**
- **Model:** `llama-3.3-70b-versatile` (free tier)
- **Messages Format:** List of `{"role": "user/assistant/system", "content": "..."}`
- **API Key:** From `GROQ_API_KEY` environment variable

### 3. **Message Roles:**
- `user` - User's messages
- `assistant` - AI responses
- `system` - System prompt (set once per session)

---

## Required Fixes

1. **Add router registrations** (see code below)
2. **Ensure GROQ_API_KEY is in .env file**
3. **Test endpoints after adding routes**

---

## Example Usage

### Create a Chat Session:
```bash
POST /api/v1/sana/sessions/
Authorization: Bearer <token>
{
  "is_active": true
}
```

### Send a Message (triggers Groq):
```bash
POST /api/v1/sana/sessions/1/messages/
Authorization: Bearer <token>
{
  "message": "Hello, I'm feeling anxious today"
}
```

### Response:
```json
{
  "id": 123,
  "session": 1,
  "sender": "user",
  "message": "Hello, I'm feeling anxious today",
  "timestamp": "2025-01-15T10:00:00Z"
}
```

**Then automatically:**
- Groq generates AI response
- AI message saved with `sender: "ai"`

---

## Groq Service Code

```python
# obeeomaapp/Services/groq_service.py
class GroqService:
    def __init__(self):
        self.client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

    def get_response(self, user_message, conversation_history):
        messages = []
        for msg in conversation_history:
            messages.append({"role": msg["role"], "content": msg["content"]})
        messages.append({"role": "user", "content": user_message})
        
        chat_completion = self.client.chat.completions.create(
            messages=messages,
            model="llama-3.3-70b-versatile",
        )
        
        return chat_completion.choices[0].message.content
```

---

## Important Notes

1. **Nested Routes:** ChatMessageView uses nested routing (`/sessions/{id}/messages/`)
2. **Permission:** Both views require `IsAuthenticated`
3. **User Isolation:** Users can only access their own sessions/messages
4. **Error Handling:** Groq errors are caught and return 500 with error message
