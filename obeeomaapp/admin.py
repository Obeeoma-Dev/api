"""from django.contrib import admin
from obeeomaapp.models import (
    User,
    Organization,
    Client,
    Subscription,
    ClientEngagement,
    FeatureFlag,
    CrisisHotline,
    HotlineActivity,
    RecentActivity,
)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "role", "onboarding_completed", "is_suspended", "mfa_enabled")
    list_filter = ("role", "onboarding_completed", "is_suspended", "mfa_enabled")
    search_fields = ("username", "email")


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name",)
    search_fields = ("name",)


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ("name", "organization")
    list_filter = ("organization",)
    search_fields = ("name",)


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ("organization", "plan", "Subscriptions", "start_date", "is_active")
    list_filter = ("plan", "is_active")
    search_fields = ("organization__name",)


@admin.register(ClientEngagement)
class ClientEngagementAdmin(admin.ModelAdmin):
    list_display = ("organization", "engagement_rate", "month")
    list_filter = ("month", "organization")
    search_fields = ("organization__name",)


@admin.register(FeatureFlag)
class FeatureFlagAdmin(admin.ModelAdmin):
    list_display = ("organization", "feature_name", "usage_count")
    search_fields = ("feature_name", "organization__name")


@admin.register(CrisisHotline)
class CrisisHotlineAdmin(admin.ModelAdmin):
    list_display = ("organization", "contact_number", "description")
    search_fields = ("organization__name", "contact_number")

@admin.register(HotlineActivity)
class HotlineActivityAdmin(admin.ModelAdmin):
    list_display = ("organization", "call_count", "spike_percentage", "recorded_at")
    list_filter = ("recorded_at",)
    search_fields = ("organization__name",)


@admin.register(RecentActivity)
class RecentActivityAdmin(admin.ModelAdmin):
    list_display = ("organization", "activity_type", "details", "timestamp", "is_important")
    list_filter = ("is_important", "timestamp")
    search_fields = ("organization__name", "activity_type", "details")"""
