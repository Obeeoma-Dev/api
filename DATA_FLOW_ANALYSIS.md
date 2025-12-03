# DATA FLOW: Mobile App (Employee) → Database → Web App (Employer)

## Overview
Both apps use the SAME Django REST API, so data flows automatically between them through the shared database.

---

## 1. EMPLOYEE ACTIONS (Mobile App) → DATABASE

### When Employee Uses Mobile App:

#### A. Takes Assessment (PHQ-9/GAD-7)
**Mobile App:**
```
POST /api/v1/assessments/responses/
{
  "assessment_type": "PHQ-9",
  "responses": [
    {"question_id": 1, "score": 2},
    {"question_id": 2, "score": 1},
    ...
  ]
}
```

**What Happens:**
- `AssessmentResponseViewSet.create()` saves to `AssessmentResponse` table
- Calculates `total_score` and `severity_level`
- Links to employee's `user` account

**Database Tables Updated:**
- ✅ `obeeomaapp_assessmentresponse` (new row added)

---

#### B. Tracks Mood
**Mobile App:**
```
POST /api/v1/employee/mood-tracking/
{
  "mood": "happy",
  "note": "Feeling great today!"
}
```

**What Happens:**
- `MoodTrackingView.create()` saves to `MoodTracking` table
- Links to employee's user account

**Database Tables Updated:**
- ✅ `obeeomaapp_moodtracking` (new row added)

---

#### C. Uses AI Chatbot
**Mobile App:**
```
POST /api/v1/sana/sessions/
POST /api/v1/sana/messages/
```

**What Happens:**
- Creates chat session and messages
- Tracks AI usage

**Database Tables Updated:**
- ✅ `sana_ai_chatsession` (new row added)
- ✅ `sana_ai_chatmessage` (new rows added)

---

#### D. Saves Resources
**Mobile App:**
```
POST /api/v1/saved/
{
  "video_id": 5
}
```

**What Happens:**
- `SavedResourceViewSet.create()` saves to `SavedResource` table

**Database Tables Updated:**
- ✅ `obeeomaapp_savedresource` (new row added)

---

## 2. EMPLOYER VIEWS DATA (Web App) ← DATABASE

### When Employer Opens Dashboard:

**Web App:**
```
GET /api/v1/dashboard/organization-overview/
```

**What Happens:**
`OrganizationOverviewView.list()` queries the database:

```python
# Gets employees for this employer
employee_queryset = Employee.objects.filter(employer=employer)

# Queries assessment data created by mobile app
AssessmentResponse.objects.filter(
    user__in=employee_queryset.values_list('user', flat=True)
)

# Queries mood tracking data created by mobile app
MoodTracking.objects.filter(
    user__in=employee_queryset.values_list('user', flat=True)
)

# Queries AI chatbot usage created by mobile app
ChatSession.objects.filter(
    user__in=employee_queryset.values_list('user', flat=True)
)

# Queries saved resources created by mobile app
SavedResource.objects.filter(
    user__in=employee_queryset.values_list('user', flat=True)
)
```

**Returns to Web App:**
```json
{
  "summary": {
    "total_employees": 436,
    "wellness_index": 61,
    "at_risk": 0
  },
  "employees": {
    "list": [...],
    "total": 436
  },
  "engagement_trend": {
    "active": 345,
    "inactive": 91
  },
  "feature_usage": {
    "wellness_assessments": 80,  // % who used mobile app assessments
    "ai_chatbot": 80,             // % who used mobile app chatbot
    "mood_tracking": 50,          // % who used mobile app mood tracking
    "resource_library": 50        // % who saved resources on mobile
  },
  "mood_trend": [
    {"week": 1, "value": 62.5},  // From mobile app mood entries
    ...
  ],
  "notifications": [...]
}
```

---

## 3. THE CONNECTION MECHANISM

### How They're Connected:

#### A. **User Authentication** (Links Everything)
```
Employee (Mobile) → User Account → Employee Profile → Employer
                         ↓
                    (user_id links all data)
```

When employee logs in on mobile:
```
POST /api/v1/auth/login/
{
  "email": "employee@company.com",
  "password": "password123"
}

Response:
{
  "access": "jwt_token_here",
  "user": {
    "id": 5,  // This user_id links all their data
    "email": "employee@company.com"
  }
}
```

#### B. **Database Relationships**
```sql
-- Employee belongs to Employer
Employee.employer_id → Employer.id

-- All employee actions link to User
AssessmentResponse.user_id → User.id
MoodTracking.user_id → User.id
ChatSession.user_id → User.id
SavedResource.user_id → User.id

-- User links to Employee
User.id → Employee.user_id → Employee.employer_id → Employer.id
```

#### C. **Employer Dashboard Query**
```python
# 1. Get all employees for this employer
employees = Employee.objects.filter(employer=employer)

# 2. Get all user IDs for these employees
user_ids = employees.values_list('user', flat=True)

# 3. Query all data created by these users (from mobile app)
assessments = AssessmentResponse.objects.filter(user__in=user_ids)
moods = MoodTracking.objects.filter(user__in=user_ids)
chats = ChatSession.objects.filter(user__in=user_ids)
resources = SavedResource.objects.filter(user__in=user_ids)
```

---

## 4. REAL-TIME DATA FLOW

### Timeline Example:

**10:00 AM** - Employee opens mobile app
- Logs in with JWT token
- User ID: 5, Employee ID: 10, Employer ID: 2

**10:05 AM** - Employee takes PHQ-9 assessment on mobile
```
POST /api/v1/assessments/responses/
```
- Saves to database: `AssessmentResponse(user_id=5, total_score=12, severity_level="Moderate")`

**10:10 AM** - Employer opens web dashboard
```
GET /api/v1/dashboard/organization-overview/
```
- Queries: `AssessmentResponse.objects.filter(user__in=[5, 8, 12, ...])`
- **Immediately sees** the assessment the employee just took!
- Wellness index updates
- At-risk count updates if severity is high

**10:15 AM** - Employee tracks mood on mobile
```
POST /api/v1/employee/mood-tracking/
```
- Saves to database: `MoodTracking(user_id=5, mood="happy")`

**10:20 AM** - Employer refreshes dashboard
- **Immediately sees** updated mood trend chart
- Engagement metrics update

---

## 5. KEY POINTS

### ✅ Already Connected:
1. **Same Database** - Both apps read/write to PostgreSQL
2. **Same API** - Both apps use Django REST API endpoints
3. **Same Authentication** - JWT tokens for both platforms
4. **Real-time** - Data is available immediately after employee actions

### ✅ No Additional Setup Needed:
- Mobile app creates data → Database stores it
- Web app queries database → Gets latest data
- Everything is linked via `user_id` and `employer_id`

### ✅ Data Privacy:
- Employer only sees data from THEIR employees
- Filtered by: `Employee.objects.filter(employer=employer)`
- Each employer sees only their organization's data

---

## 6. VERIFICATION CHECKLIST

To verify the connection is working:

### Step 1: Employee Creates Data (Mobile)
```bash
# Employee logs in
POST /api/v1/auth/login/

# Employee takes assessment
POST /api/v1/assessments/responses/
{
  "assessment_type": "PHQ-9",
  "responses": [...]
}
```

### Step 2: Check Database
```sql
SELECT * FROM obeeomaapp_assessmentresponse 
WHERE user_id = <employee_user_id>;
```

### Step 3: Employer Views Data (Web)
```bash
# Employer logs in
POST /api/v1/auth/login/

# Employer views dashboard
GET /api/v1/dashboard/organization-overview/
```

### Step 4: Verify Data Appears
- Assessment should appear in wellness_index calculation
- Employee should appear in employees list
- Feature usage should show assessment completion

---

## 7. TROUBLESHOOTING

If data doesn't appear on employer dashboard:

### Check 1: Employee-Employer Link
```python
# Verify employee is linked to employer
employee = Employee.objects.get(user_id=<employee_user_id>)
print(employee.employer_id)  # Should match employer's ID
```

### Check 2: User Authentication
```python
# Verify user exists and is linked
user = User.objects.get(id=<user_id>)
employee = Employee.objects.get(user=user)
print(employee.employer.name)  # Should show employer name
```

### Check 3: Data Exists
```python
# Verify data was created
AssessmentResponse.objects.filter(user_id=<user_id>).count()
MoodTracking.objects.filter(user_id=<user_id>).count()
```

---

## CONCLUSION

**The mobile app and web app are ALREADY CONNECTED through:**
1. Shared Django REST API
2. Shared PostgreSQL database
3. User authentication (JWT)
4. Database relationships (user_id → employee_id → employer_id)

**No additional configuration needed!** 

When an employee uses the mobile app, their data is immediately available to their employer on the web dashboard through the shared database.
