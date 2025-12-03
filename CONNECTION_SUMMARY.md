# 📱 Mobile App ↔️ 🌐 Web App Connection

## TL;DR: **They're Already Connected!** ✅

Both apps use the **SAME Django REST API** and **SAME PostgreSQL Database**.

---

## Simple Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         DJANGO REST API                         │
│                    (Single Backend Server)                      │
└─────────────────────────────────────────────────────────────────┘
         ▲                                              ▲
         │                                              │
         │ JWT Auth                          JWT Auth  │
         │ API Calls                        API Calls  │
         │                                              │
┌────────┴────────┐                          ┌─────────┴─────────┐
│  📱 Mobile App  │                          │  🌐 Web App       │
│   (Employee)    │                          │   (Employer)      │
│                 │                          │                   │
│ • Take Tests    │                          │ • View Dashboard  │
│ • Track Mood    │                          │ • See Employees   │
│ • Use Chatbot   │                          │ • View Analytics  │
│ • Save Resources│                          │ • Send Invites    │
└─────────────────┘                          └───────────────────┘
```

---

## How Data Flows

### 1️⃣ Employee Uses Mobile App

```javascript
// Mobile app makes API call
fetch('https://api.yourapp.com/api/v1/assessments/responses/', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer <employee_jwt_token>',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    assessment_type: 'PHQ-9',
    responses: [...]
  })
})
```

**Django Backend:**
```python
# AssessmentResponseViewSet.create()
def perform_create(self, serializer):
    serializer.save(user=self.request.user)  # Links to employee's user
```

**Database:**
```sql
INSERT INTO obeeomaapp_assessmentresponse 
(user_id, assessment_type, total_score, severity_level, ...)
VALUES (5, 'PHQ-9', 12, 'Moderate', ...);
```

---

### 2️⃣ Employer Views Web Dashboard

```javascript
// Web app makes API call
fetch('https://api.yourapp.com/api/v1/dashboard/organization-overview/', {
  method: 'GET',
  headers: {
    'Authorization': 'Bearer <employer_jwt_token>'
  }
})
```

**Django Backend:**
```python
# OrganizationOverviewView.list()
def list(self, request):
    # Get employer's employees
    employee_queryset = Employee.objects.filter(employer=employer)
    
    # Get assessments from those employees (created via mobile app!)
    assessments = AssessmentResponse.objects.filter(
        user__in=employee_queryset.values_list('user', flat=True)
    )
    
    # Calculate wellness index from mobile app data
    avg_score = assessments.aggregate(avg=Avg('total_score'))['avg']
    wellness_index = int(100 - (avg_score / 27 * 100))
    
    return Response({
        'wellness_index': wellness_index,
        'total_employees': employee_queryset.count(),
        ...
    })
```

**Database Query:**
```sql
-- Get all employees for this employer
SELECT * FROM obeeomaapp_employee WHERE employer_id = 2;

-- Get assessments from those employees
SELECT * FROM obeeomaapp_assessmentresponse 
WHERE user_id IN (5, 8, 12, 15, ...);
```

---

## The Magic: Database Relationships

```
┌──────────┐
│   User   │ ← JWT token identifies this
│  id: 5   │
└────┬─────┘
     │
     │ user_id (OneToOne)
     ▼
┌──────────┐
│ Employee │
│  id: 10  │
│ user: 5  │ ← Links user to employee
└────┬─────┘
     │
     │ employer_id (ForeignKey)
     ▼
┌──────────┐
│ Employer │ ← Employer sees all their employees' data
│  id: 2   │
└──────────┘

All employee data links back to User:
┌─────────────────────┐
│ AssessmentResponse  │
│ user_id: 5          │ ← Created by mobile app
└─────────────────────┘

┌─────────────────────┐
│ MoodTracking        │
│ user_id: 5          │ ← Created by mobile app
└─────────────────────┘

┌─────────────────────┐
│ ChatSession         │
│ user_id: 5          │ ← Created by mobile app
└─────────────────────┘

Employer queries:
"Show me data for all users where user.employee.employer = my_employer"
```

---

## API Endpoints (Same for Both Apps)

### Employee Endpoints (Mobile App Uses These):
```
POST   /api/v1/auth/login/                    - Login
POST   /api/v1/assessments/responses/         - Submit assessment
GET    /api/v1/assessments/questions/         - Get questions
POST   /api/v1/employee/mood-tracking/        - Track mood
POST   /api/v1/sana/sessions/                 - Start AI chat
POST   /api/v1/saved/                         - Save resource
GET    /api/v1/employee/profile/              - Get profile
```

### Employer Endpoints (Web App Uses These):
```
POST   /api/v1/auth/login/                    - Login
GET    /api/v1/dashboard/organization-overview/ - Dashboard data
GET    /api/v1/dashboard/employees/           - Employee list
POST   /api/v1/invitations/                   - Send invitation
GET    /api/v1/dashboard/wellness-reports/    - Reports
```

**Key Point:** Both apps hit the **SAME API server**, just different endpoints!

---

## Authentication Flow

### Mobile App (Employee):
```
1. Employee logs in
   POST /api/v1/auth/login/
   { "email": "employee@company.com", "password": "..." }

2. Gets JWT token
   { "access": "eyJhbGc...", "user": { "id": 5 } }

3. All requests include token
   Authorization: Bearer eyJhbGc...

4. Backend identifies user_id = 5
   → Finds Employee(user_id=5, employer_id=2)
   → Saves data linked to user_id = 5
```

### Web App (Employer):
```
1. Employer logs in
   POST /api/v1/auth/login/
   { "email": "employer@company.com", "password": "..." }

2. Gets JWT token
   { "access": "eyJhbGc...", "user": { "id": 1 } }

3. All requests include token
   Authorization: Bearer eyJhbGc...

4. Backend identifies user_id = 1
   → Finds Employer linked to this user
   → Queries all employees where employer_id = 2
   → Returns aggregated data from those employees
```

---

## Real Example

### Scenario: Employee takes assessment on mobile

**Mobile App (10:00 AM):**
```javascript
// Employee submits PHQ-9 assessment
POST /api/v1/assessments/responses/
{
  "assessment_type": "PHQ-9",
  "responses": [
    {"question_id": 1, "score": 2},
    {"question_id": 2, "score": 3},
    ...
  ]
}

// Response:
{
  "id": 123,
  "user": 5,
  "assessment_type": "PHQ-9",
  "total_score": 18,
  "severity_level": "Moderately Severe",
  "completed_at": "2025-11-15T10:00:00Z"
}
```

**Database (10:00 AM):**
```sql
-- New row inserted
INSERT INTO obeeomaapp_assessmentresponse VALUES
(123, 5, 'PHQ-9', 18, 'Moderately Severe', '2025-11-15 10:00:00');
```

**Web App (10:05 AM):**
```javascript
// Employer refreshes dashboard
GET /api/v1/dashboard/organization-overview/

// Response includes:
{
  "summary": {
    "total_employees": 50,
    "wellness_index": 58,  // ← Calculated from employee's assessment!
    "at_risk": 1           // ← Employee now shows as at-risk!
  },
  "feature_usage": {
    "wellness_assessments": 82  // ← Increased by 2% (1 more employee)
  }
}
```

**The employer IMMEDIATELY sees the employee's assessment data!**

---

## Configuration Check

### Both apps should use the same API URL:

**Mobile App (React Native):**
```javascript
// config.js or .env
const API_URL = 'https://api.yourapp.com/api/v1';

// or for development
const API_URL = 'http://192.168.1.100:8000/api/v1';
```

**Web App (React/Next.js):**
```javascript
// config.js or .env
const API_URL = 'https://api.yourapp.com/api/v1';

// or for development
const API_URL = 'http://localhost:8000/api/v1';
```

**Django Backend:**
```python
# settings.py
ALLOWED_HOSTS = ['api.yourapp.com', 'localhost', '192.168.1.100']

CORS_ALLOWED_ORIGINS = [
    'http://localhost:3000',      # Web app dev
    'https://webapp.yourapp.com', # Web app prod
    'http://localhost:19000',     # Mobile app dev (Expo)
]
```

---

## Verification Steps

### Test the Connection:

1. **Create test employee via invitation:**
   ```bash
   # Web app (employer)
   POST /api/v1/invitations/
   { "email": "test@employee.com" }
   ```

2. **Accept invitation and create account:**
   ```bash
   # Mobile app (employee)
   PUT /api/v1/auth/accept-invite/
   { "token": "...", "password": "..." }
   ```

3. **Employee takes assessment:**
   ```bash
   # Mobile app
   POST /api/v1/assessments/responses/
   { "assessment_type": "PHQ-9", "responses": [...] }
   ```

4. **Check employer dashboard:**
   ```bash
   # Web app
   GET /api/v1/dashboard/organization-overview/
   # Should show the assessment data!
   ```

---

## Summary

### ✅ What's Already Working:

1. **Same API** - Both apps use your Django REST API
2. **Same Database** - Both read/write to PostgreSQL
3. **Same Authentication** - JWT tokens for both
4. **Linked Data** - Employee data automatically appears for employer
5. **Real-time** - Data available immediately after creation

### ✅ No Additional Setup Needed:

The connection is **automatic** through:
- Database foreign keys (Employee → Employer)
- User authentication (JWT tokens)
- API endpoint design (employer queries filter by their employees)

### 🎯 Key Takeaway:

**When an employee uses the mobile app, their employer IMMEDIATELY sees the data on the web dashboard** because both apps share the same backend and database!
