# Utilities package
# yourapp/services.py
from django.db.models import Count
from .models import EmployeeEngagement

def calculate_engagement(employer, month):
    total = employer.employees.count()
    active = employer.employees.filter(status='active').count()
    rate = (active / total) * 100 if total else 0

    engagement, _ = EmployeeEngagement.objects.update_or_create(
        employer=employer,
        month=month,
        defaults={'engagement_rate': rate}
    )
    return engagement
