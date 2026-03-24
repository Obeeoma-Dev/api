# WELLNESS GRAPH API DOCUMENTATION

## Overview
The Wellness Graph API provides mood trend visualization for employees by converting mood tracking entries into numeric scores suitable for charting.

## Base URL
All endpoints are prefixed with: `/api/wellness-graph/`

## Mood Score Conversion
The system converts mood names to numeric scores (0-5 scale):

- **5** - Ecstatic
- **4** - Happy, Excited  
- **3** - Content, Calm
- **2** - Neutral, Tired
- **1** - Anxious, Stressed, Sad, Frustrated
- **0** - Angry

## Available Endpoints

### 1. List Wellness Graph Entries
**URL:** `GET /api/wellness-graph/`
**Description:** Get all wellness graph entries for the authenticated user

**Response:**
```json
[
    {
        "id": 1,
        "user": 1,
        "mood_score": 4,
        "mood_date": "2024-01-15"
    }
]
```

### 2. Create Wellness Graph Entry
**URL:** `POST /api/wellness-graph/`
**Description:** Manually create a wellness graph entry

**Request Body:**
```json
{
    "mood_score": 4,
    "mood_date": "2024-01-15"
}
```

### 3. Sync from Mood Tracking
**URL:** `GET /api/wellness-graph/sync-from-mood-tracking/`
**Description:** Automatically sync all mood tracking entries to wellness graph

**Response:**
```json
{
    "message": "Successfully synced mood tracking data to wellness graph",
    "synced_entries": 15,
    "updated_entries": 3,
    "total_processed": 18
}
```

### 4. Get Chart Data
**URL:** `GET /api/wellness-graph/chart-data/`
**Description:** Get wellness graph data optimized for frontend charts

**Query Parameters:**
- `days` (optional): Number of days to include (default: 30)

**Response:**
```json
{
    "data": [
        {
            "date": "2024-01-15",
            "score": 4,
            "mood_label": "Happy/Excited"
        }
    ],
    "statistics": {
        "average_score": 3.2,
        "max_score": 5,
        "min_score": 1,
        "total_days": 30,
        "trend": "improving"
    },
    "period": "last_30_days"
}
```

### 5. Auto Sync Latest
**URL:** `POST /api/wellness-graph/auto-sync/`
**Description:** Sync the latest mood tracking entry to wellness graph

**Response:**
```json
{
    "message": "Auto-sync completed",
    "mood_date": "2024-01-15",
    "mood_score": 4,
    "original_mood": "Happy",
    "was_created": true
}
```

## Automatic Sync Features

### 1. Real-time Sync
When employees create mood tracking entries via `/api/employee/mood-tracking/entries/`, the system automatically:
- Converts the mood name to a numeric score
- Creates/updates the corresponding wellness graph entry
- Ensures the graph is always up-to-date

### 2. Smart Chart Data
The `/chart-data/` endpoint automatically:
- Attempts to sync from mood tracking if no wellness graph data exists
- Calculates trend analysis (improving/declining/stable)
- Provides statistics for dashboard visualization
- Formats data optimally for frontend chart libraries

### 3. Trend Analysis
The system calculates trends by comparing:
- **Last 7 days average** vs **Previous 7 days average**
- Returns: `improving`, `declining`, `stable`, or `insufficient_data`

## Frontend Integration

### React Example
```javascript
// Get wellness chart data
const getWellnessChart = async (days = 30) => {
    try {
        const response = await fetch(`/api/wellness-graph/chart-data/?days=${days}`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        // Update chart with data.data
        updateChart(data.data);
        
        // Display statistics
        displayStats(data.statistics);
        
    } catch (error) {
        console.error('Error fetching wellness data:', error);
    }
};

// Sync mood tracking to wellness graph
const syncMoodData = async () => {
    try {
        const response = await fetch('/api/wellness-graph/sync-from-mood-tracking/', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        console.log('Sync result:', result);
        
    } catch (error) {
        console.error('Error syncing mood data:', error);
    }
};
```

### Chart.js Integration
```javascript
const wellnessCtx = document.getElementById('wellnessChart').getContext('2d');

const wellnessChart = new Chart(wellnessCtx, {
    type: 'line',
    data: {
        labels: chartData.map(item => item.date),
        datasets: [{
            label: 'Mood Score',
            data: chartData.map(item => item.score),
            borderColor: 'rgb(75, 192, 192)',
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            tension: 0.4
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: {
                beginAtZero: true,
                max: 5,
                ticks: {
                    stepSize: 1,
                    callback: function(value) {
                        const labels = ['', 'Angry', 'Anxious', 'Neutral', 'Content', 'Happy', 'Ecstatic'];
                        return labels[value] || value;
                    }
                }
            }
        },
        plugins: {
            tooltip: {
                callbacks: {
                    label: function(context) {
                        return `Mood: ${context.parsed.y} (${chartData[context.dataIndex].mood_label})`;
                    }
                }
            }
        }
    }
});
```

## Usage Examples

### 1. Initial Setup
```bash
# Sync all existing mood tracking data
curl -X GET http://localhost:8000/api/wellness-graph/sync-from-mood-tracking/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 2. Get Chart Data
```bash
# Get last 30 days of wellness data
curl -X GET "http://localhost:8000/api/wellness-graph/chart-data/?days=30" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Get last 7 days
curl -X GET "http://localhost:8000/api/wellness-graph/chart-data/?days=7" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 3. Auto Sync Latest Entry
```bash
# Sync the most recent mood tracking entry
curl -X POST http://localhost:8000/api/wellness-graph/auto-sync/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Benefits for Frontend

1. **Real-time Updates**: Mood tracking automatically updates wellness graph
2. **Chart-Ready Data**: Pre-formatted for popular chart libraries
3. **Trend Analysis**: Built-in trend calculations
4. **Flexible Time Ranges**: Support for any date range
5. **Error Handling**: Graceful fallbacks and sync attempts
6. **Statistics**: Pre-calculated averages, min/max, trends

## Troubleshooting

### Issue: No wellness graph data
**Solution**: Call `/sync-from-mood-tracking/` to populate from existing mood entries

### Issue: Chart shows old data
**Solution**: Call `/auto-sync/` to sync the latest mood entry

### Issue: Trend shows "insufficient_data"
**Solution**: Need at least 14 days of data for trend analysis

## Security Notes

- Users can only access their own wellness graph data
- Automatic sync respects user permissions
- All endpoints require authentication
- No cross-user data exposure
