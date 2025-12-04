# 🚀 Quick Start Guide

## ✅ What's Already Done:
1. ✅ OpenAI API key added to .env
2. ✅ All code implemented (views, models, serializers)
3. ✅ Assessment system ready
4. ✅ Sana AI configured
5. ✅ Employer dashboard ready
6. ✅ Employee invitation system ready

---

## 📋 Final Steps (Run These Commands):

### 1. Install OpenAI Package
```bash
pip install openai
```

### 2. Run Database Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### 3. Populate Assessment Questions
```bash
python populate_assessments.py
```

### 4. Create Admin User (Optional)
```bash
python manage.py createsuperuser
```

### 5. Verify Setup
```bash
python verify_setup.py
```

### 6. Start Server
```bash
python manage.py runserver
```

---

## 🧪 Test Your API

### Test 1: Get Assessment Questions
```bash
curl http://localhost:8000/api/v1/assessments/questions/
```

### Test 2: Login (after creating user)
```bash
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```

### Test 3: Chat with Sana AI
```bash
curl -X POST http://localhost:8000/api/v1/sana/chat/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "I feel anxious"}'
```

---

## 📱 Connect Mobile/Web Apps

Both apps should point to:
```
API_URL = http://localhost:8000/api/v1/
# or your production URL
```

---

## 🎯 Key Endpoints

### Authentication
- POST `/api/v1/auth/signup/` - Register
- POST `/api/v1/auth/login/` - Login
- POST `/api/v1/auth/logout/` - Logout

### Assessments
- GET `/api/v1/assessments/questions/` - Get questions
- POST `/api/v1/assessments/responses/` - Submit assessment
- GET `/api/v1/assessments/responses/history/` - View history

### Sana AI Chatbot
- POST `/api/v1/sana/chat/` - Chat with AI

### Employer Dashboard
- GET `/api/v1/dashboard/organization-overview/` - Dashboard data
- POST `/api/v1/invitations/` - Send employee invitation

### Employee Features
- POST `/api/v1/employee/mood-tracking/` - Track mood
- GET `/api/v1/employee/profile/` - Get profile

---

## ✅ You're Ready When:
- [ ] `pip install openai` completed
- [ ] `python manage.py migrate` completed
- [ ] `python populate_assessments.py` completed
- [ ] `python verify_setup.py` shows all ✅
- [ ] Server starts without errors

Then you can connect your mobile and web apps! 🎉
