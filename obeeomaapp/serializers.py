# obeeomaapp/serializers.py
from rest_framework import serializers

from .models import (
    Organization,
    Client,
    AIManagement,
    HotlineActivity,
    ClientEngagement,
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

class AIManagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIManagement
        fields = ['id', 'organization', 'title', 'description', 'effectiveness', 'created_at']

class HotlineActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = HotlineActivity
        fields = ['id', 'organization', 'call_count', 'spike_percentage', 'recorded_at']

class ClientEngagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientEngagement
        fields = ['id', 'organization', 'engagement_rate', 'month']

class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = ['id', 'organization', 'plan', 'subscriptions', 'start_date', 'end_date']

class RecentActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = RecentActivity
        fields = ['id', 'organization', 'activity_type', 'details', 'timestamp']

