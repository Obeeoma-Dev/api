from rest_framework import serializers
from .models import (
    Organization,
    Client,
    AIRecommendation,
    HotlineActivity,
    PatientEngagement,
    Subscription,
    RecentActivity
)

class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'

class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = ['id', 'organization', 'name', 'email', 'joined_date']

class AIRecommendationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIRecommendation
        fields = ['id', 'organization', 'title', 'description', 'effectiveness', 'created_at']

class HotlineActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = HotlineActivity
        fields = ['id', 'organization', 'call_count', 'spike_percentage', 'recorded_at']

class ClientEngagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = PatientEngagement
        fields = ['id', 'organization', 'engagement_rate', 'month']

class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = ['id', 'organization', 'plan', 'revenue', 'start_date', 'end_date']

class RecentActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = RecentActivity
        fields = ['id', 'organization', 'activity_type', 'details', 'timestamp']
