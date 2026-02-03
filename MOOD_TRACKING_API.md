# MOOD TRACKING API ENDPOINTS

This document outlines all the new mood tracking endpoints that have been added to the Obeeoma API.

## Base URL
All endpoints are prefixed with: `/api/employee/mood-tracking/`

## Available Endpoints

### 1. SCREEN - `/api/employee/mood-tracking/screen/`
**Method:** GET  
**Description:** Get mood tracking screen overview  
**Response:**
```json
{
    "has_checked_in_today": true,
    "today_mood": "Happy",
    "current_streak": 5,
    "recent_entries_count": 7,
    "mood_categories": {
        "Ecstatic": "Positive",
        "Happy": "Positive",
        "Excited": "Positive",
        "Content": "Positive",
        "Calm": "Neutral",
        "Neutral": "Neutral",
        "Tired": "Neutral",
        "Anxious": "Negative",
        "Stressed": "Negative",
        "Sad": "Negative",
        "Frustrated": "Negative",
        "Angry": "Negative"
    }
}
```

### 2. ENTRIES - `/api/employee/mood-tracking/entries/`
**Methods:** GET, POST  
**Description:** Get or create mood entries  

**GET Query Parameters:**
- `start_date` (optional): Filter entries from this date (YYYY-MM-DD)
- `end_date` (optional): Filter entries until this date (YYYY-MM-DD)

**GET Response:**
```json
[
    {
        "id": 1,
        "mood": "Happy",
        "note": "Had a great day at work!",
        "checked_in_at": "2024-01-15T10:30:00Z"
    }
]
```

**POST Request Body:**
```json
{
    "mood": "Happy",
    "note": "Optional note about your mood"
}
```

**POST Response:** 201 Created with the new mood entry

### 3. TODAY - `/api/employee/mood-tracking/today/`
**Methods:** GET, PUT  
**Description:** Get or update today's mood  

**GET Response:**
```json
{
    "id": 1,
    "mood": "Happy",
    "note": "Feeling good today!",
    "checked_in_at": "2024-01-15T10:30:00Z"
}
```

**PUT Request Body:**
```json
{
    "mood": "Content",
    "note": "Updated note"
}
```

### 4. CHART - `/api/employee/mood-tracking/chart/`
**Method:** GET  
**Description:** Get mood data for chart visualization  

**Query Parameters:**
- `period` (optional): Number of days to include (default: 30)

**Response:**
```json
{
    "period": "last_30_days",
    "data": [
        {
            "date": "2024-01-15",
            "mood": "Happy",
            "value": 4,
            "note": "Good day"
        }
    ],
    "average_mood": 3.5
}
```

### 5. ANALYTICS - `/api/employee/mood-tracking/analytics/`
**Method:** GET  
**Description:** Get comprehensive mood analytics  

**Query Parameters:**
- `period` (optional): Number of days to analyze (default: 30)

**Response:**
```json
{
    "period": "last_30_days",
    "total_entries": 25,
    "mood_distribution": [
        {"mood": "Happy", "count": 10},
        {"mood": "Neutral", "count": 8}
    ],
    "category_distribution": {
        "Positive": 15,
        "Neutral": 8,
        "Negative": 2
    },
    "weekly_pattern": {
        "Monday": {
            "count": 4,
            "most_common": "Happy"
        }
    },
    "current_streak": 5,
    "longest_streak": 12,
    "check_in_rate": 83.3
}
```

### 6. HISTORY - `/api/employee/mood-tracking/history/`
**Method:** GET  
**Description:** Get mood history with pagination  

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page (default: 20)
- `start_date` (optional): Filter from this date
- `end_date` (optional): Filter until this date

**Response:**
```json
{
    "entries": [
        {
            "id": 1,
            "mood": "Happy",
            "note": "Good day",
            "checked_in_at": "2024-01-15T10:30:00Z"
        }
    ],
    "pagination": {
        "page": 1,
        "page_size": 20,
        "total_count": 50,
        "total_pages": 3
    }
}
```

### 7. PATTERNS - `/api/employee/mood-tracking/patterns/`
**Method:** GET  
**Description:** Analyze mood patterns and trends  

**Query Parameters:**
- `period` (optional): Number of days to analyze (default: 90)

**Response:**
```json
{
    "patterns": {
        "morning_most_common": "Happy",
        "morning_entry_count": 12,
        "afternoon_most_common": "Neutral",
        "afternoon_entry_count": 8,
        "evening_most_common": "Calm",
        "evening_entry_count": 10,
        "monday_most_common": "Happy",
        "mood_sequences": [
            {
                "mood": "Happy",
                "length": 4,
                "start_date": "2024-01-10"
            }
        ],
        "trend": "improving"
    }
}
```

### 8. INSIGHTS - `/api/employee/mood-tracking/insights/`
**Method:** GET  
**Description:** Get personalized mood insights  

**Query Parameters:**
- `period` (optional): Number of days to analyze (default: 30)

**Response:**
```json
{
    "insights": [
        {
            "type": "most_common_mood",
            "title": "Your most common mood is Happy",
            "description": "You've logged this mood 10 times in the last 30 days.",
            "priority": "medium"
        },
        {
            "type": "consistency",
            "title": "Great consistency!",
            "description": "You've checked in 83.3% of days. Keep it up!",
            "priority": "positive"
        }
    ],
    "generated_at": "2024-01-15T10:30:00Z",
    "period": "last_30_days"
}
```

### 9. UNREAD INSIGHTS - `/api/employee/mood-tracking/unread-insights/`
**Method:** GET  
**Description:** Get unread mood insights  

**Response:**
```json
{
    "unread_count": 2,
    "insights": [
        {
            "type": "most_common_mood",
            "title": "Your most common mood is Happy",
            "description": "You've logged this mood 10 times in the last 30 days.",
            "priority": "medium"
        }
    ]
}
```

### 10. MARK READ - `/api/employee/mood-tracking/mark-read/`
**Method:** POST  
**Description:** Mark insights as read  

**Response:**
```json
{
    "message": "Insights marked as read",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

## Mood Categories

The system supports the following mood categories:

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

## Error Responses

All endpoints return appropriate HTTP status codes and error messages:

- **400 Bad Request**: Invalid input data
- **401 Unauthorized**: Authentication required
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Server error

Example error response:
```json
{
    "error": "Mood is required"
}
```

## Usage Examples

### Creating a new mood entry
```bash
curl -X POST http://localhost:8000/api/employee/mood-tracking/entries/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mood": "Happy",
    "note": "Great day at work!"
  }'
```

### Getting mood analytics
```bash
curl -X GET "http://localhost:8000/api/employee/mood-tracking/analytics/?period=30" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Getting mood chart data
```bash
curl -X GET "http://localhost:8000/api/employee/mood-tracking/chart/?period=7" \
  -H "Authorization: Bearer YOUR_TOKEN"
```
