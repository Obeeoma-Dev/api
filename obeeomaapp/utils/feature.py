from django.utils import timezone
from datetime import timedelta
from ..models import FeatureUsage  

class FeatureUsageCalculator:
    """
    Helper class to calculate usage percentages
    """

    @staticmethod
    def calculate_percentage_for_user(user):
        features = ['sana_ai', 'journaling', 'education', 'assessment']
        data = {}

        for feature in features:
            usage, _ = FeatureUsage.objects.get_or_create(
                user=user,
                feature=feature,
                defaults={'use_count': 0}
            )
            data[feature] = {
                "count": usage.use_count,
                "last_used": usage.last_used_at,
                "percentage": FeatureUsageCalculator._calculate_percentage(usage)
            }

        overall = round(sum(d['percentage'] for d in data.values()) / len(features), 2)
        data['overall'] = overall
        return data

    @staticmethod
    def _calculate_percentage(usage):
        now = timezone.now()
        if usage.use_count == 0:
            return 0
        last_used = usage.last_used_at
        if last_used >= now - timedelta(days=7):
            return 100
        elif last_used >= now - timedelta(days=30):
            return 70
        else:
            return 30

    @staticmethod
    def track_feature(user, feature_name):
        usage, _ = FeatureUsage.objects.get_or_create(
            user=user,
            feature=feature_name,
            defaults={'use_count': 0}
        )
        usage.increment_usage()
        return usage
