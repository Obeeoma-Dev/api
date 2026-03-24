# Company Mood Dashboard Summary Endpoint

## Endpoint Details

**URL:** `/api/v1/company-mood/dashboard_summary/`

**Method:** `GET`

**Authentication:** Required (JWT Token)

**Permission:** IsAuthenticated

---

## Description

Returns a comprehensive summary of employee moods for the organization dashboard. Shows mood statistics, breakdowns, and individual employee mood data for the last 7 days.

---

## Response Format

```json
{
  "organization": "Company Name",
  "total_employees": 50,
  "employees_with_mood_data": 35,
  "mood_summary": {
    "positive": {
      "count": 45,
      "percentage": 52.33
    },
    "neutral": {
      "count": 25,
      "percentage": 29.07
    },
    "negative": {
      "count": 16,
      "percentage": 18.6
    }
  },
  "mood_breakdown": {
    "Ecstatic": 5,
    "Happy": 15,
    "Excited": 10,
    "Content": 15,
    "Calm": 8,
    "Neutral": 12,
    "Tired": 5,
    "Anxious": 3,
    "Stressed": 5,
    "Sad": 4,
    "Frustrated": 2,
    "Angry": 1
  },
  "most_common_mood": "Happy",
  "employee_moods": [
    {
      "employee_id": 1,
      "employee_name": "John Doe",
      "mood": "Happy",
      "mood_category": "Positive",
      "checked_in_at": "2026-03-24T10:30:00Z"
    },
    {
      "employee_id": 2,
      "employee_name": "Jane Smith",
      "mood": "Stressed",
      "mood_category": "Negative",
      "checked_in_at": "2026-03-24T09:15:00Z"
    }
  ],
  "period": "Last 7 days"
}
```

---

## Response Fields

### Top Level
- **organization** (string): Organization name
- **total_employees** (integer): Total employees in organization
- **employees_with_mood_data** (integer): Employees who have checked in mood
- **period** (string): Time period for the data

### mood_summary
- **positive** (object): Positive mood statistics
  - count: Number of positive mood entries
  - percentage: Percentage of total moods
- **neutral** (object): Neutral mood statistics
  - count: Number of neutral mood entries
  - percentage: Percentage of total moods
- **negative** (object): Negative mood statistics
  - count: Number of negative mood entries
  - percentage: Percentage of total moods

### mood_breakdown
- Individual count for each mood type:
  - Ecstatic, Happy, Excited, Content (Positive)
  - Calm, Neutral, Tired (Neutral)
  - Anxious, Stressed, Sad, Frustrated, Angry (Negative)

### most_common_mood
- (string): The most frequently reported mood in the period

### employee_moods
- Array of employee mood objects with:
  - employee_id: Employee ID
  - employee_name: Employee full name or email
  - mood: Current mood
  - mood_category: Mood category (Positive/Neutral/Negative)
  - checked_in_at: When the mood was checked in

---

## Mood Categories

### Positive Moods
- Ecstatic
- Happy
- Excited
- Content

### Neutral Moods
- Calm
- Neutral
- Tired

### Negative Moods
- Anxious
- Stressed
- Sad
- Frustrated
- Angry

---

## Error Responses

### 400 Bad Request
```json
{
  "error": "User is not an employee"
}
```
**Cause:** The authenticated user is not registered as an employee

### 401 Unauthorized
```json
{
  "detail": "Authentication credentials were not provided."
}
```
**Cause:** No valid JWT token provided

---

## Usage Example

### cURL
```bash
curl -X GET "http://api.example.com/api/v1/company-mood/dashboard_summary/" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

### JavaScript/Fetch
```javascript
const response = await fetch('/api/v1/company-mood/dashboard_summary/', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});

const data = await response.json();
console.log(data);
```

### React
```jsx
import { useEffect, useState } from 'react';

function DashboardMoodSummary() {
  const [moodData, setMoodData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchMoodData = async () => {
      try {
        const token = localStorage.getItem('access_token');
        const response = await fetch('/api/v1/company-mood/dashboard_summary/', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        
        if (!response.ok) throw new Error('Failed to fetch mood data');
        
        const data = await response.json();
        setMoodData(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchMoodData();
  }, []);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div>
      <h2>{moodData.organization} - Mood Dashboard</h2>
      <p>Total Employees: {moodData.total_employees}</p>
      <p>With Mood Data: {moodData.employees_with_mood_data}</p>
      
      <div className="mood-summary">
        <div className="positive">
          Positive: {moodData.mood_summary.positive.percentage}%
        </div>
        <div className="neutral">
          Neutral: {moodData.mood_summary.neutral.percentage}%
        </div>
        <div className="negative">
          Negative: {moodData.mood_summary.negative.percentage}%
        </div>
      </div>

      <div className="employee-moods">
        {moodData.employee_moods.map(emp => (
          <div key={emp.employee_id} className="employee-mood-card">
            <h4>{emp.employee_name}</h4>
            <p>Mood: {emp.mood}</p>
            <p>Category: {emp.mood_category}</p>
            <p>Checked in: {new Date(emp.checked_in_at).toLocaleString()}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default DashboardMoodSummary;
```

---

## Notes

- Data is filtered for the last 7 days
- Only shows employees who have checked in their mood
- Requires user to be an employee in an organization
- Mood percentages are rounded to 2 decimal places
- Employee list is sorted by most recent check-in

---

## Status

✅ Implemented and tested
✅ No syntax errors
✅ System check passed
✅ Ready for frontend integration
