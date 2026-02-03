#!/usr/bin/env python
"""
Fix for Company Mood calculation issue.

PROBLEM: The mood field is a CharField but code tries to calculate Avg('mood')
SOLUTION: Map mood strings to numeric scores before aggregation
"""

# Add this to your views.py to fix the employer_mood_summary method

MOOD_SCORES = {
    "Ecstatic": 5,
    "Happy": 4,
    "Excited": 4,
    "Content": 4,
    "Calm": 3,
    "Neutral": 3,
    "Tired": 3,
    "Anxious": 2,
    "Stressed": 2,
    "Sad": 2,
    "Frustrated": 2,
    "Angry": 1,
}

# Fixed employer_mood_summary method:
"""
@action(
    detail=False,
    methods=['get'],
    url_path='employer-summary',
    permission_classes=[IsAuthenticated]
)
def employer_mood_summary(self, request):
    today = now().date()
    start_date = today - timedelta(days=6)

    qs = MoodTracking.objects.filter(
        checked_in_at__date__range=(start_date, today)
    )

    # Get all mood entries
    mood_entries = list(qs.values_list('mood', flat=True))
    
    # Calculate average using MOOD_SCORES mapping
    if mood_entries:
        mood_scores = [MOOD_SCORES.get(mood, 3) for mood in mood_entries]
        average_mood = round(sum(mood_scores) / len(mood_scores), 2)
    else:
        average_mood = 0

    # Mood distribution
    distribution = (
        qs.values('mood')
        .annotate(count=Count('mood'))
        .order_by('-count')
    )

    # Daily average with proper score mapping
    daily_data = qs.values('checked_in_at__date', 'mood')
    daily_avg_dict = {}
    
    for entry in daily_data:
        date = entry['checked_in_at__date']
        mood = entry['mood']
        score = MOOD_SCORES.get(mood, 3)
        
        if date not in daily_avg_dict:
            daily_avg_dict[date] = []
        daily_avg_dict[date].append(score)
    
    daily_avg = [
        {
            'date': date.strftime('%Y-%m-%d'),
            'avg_mood': round(sum(scores) / len(scores), 2)
        }
        for date, scores in sorted(daily_avg_dict.items())
    ]

    return Response({
        "period": "last_7_days",
        "average_mood": average_mood,
        "total_entries": qs.count(),
        "mood_distribution": list(distribution),
        "daily_average": daily_avg
    })
"""

print("Copy the fixed method above into your MoodTrackingView class")
