"""from django.contrib import admin
from obeeomaapp.models import (
    User,
    Employer,
    Employee,
    Subscription,
    EmployeeEngagement,
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


@admin.register(Employer)
class EmployerAdmin(admin.ModelAdmin):
    list_display = ("name",)
    search_fields = ("name",)


@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    list_display = ("name", "employer")
    list_filter = ("employer",)
    search_fields = ("name",)


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ("employer", "plan", "Subscriptions", "start_date", "is_active")
    list_filter = ("plan", "is_active")
    search_fields = ("employer__name",)


@admin.register(EmployeeEngagement)
class EmployeeEngagementAdmin(admin.ModelAdmin):
    list_display = ("employer", "engagement_rate", "month")
    list_filter = ("month", "employer")
    search_fields = ("employer__name",)


@admin.register(FeatureFlag)
class FeatureFlagAdmin(admin.ModelAdmin):
    list_display = ("employer", "feature_name", "usage_count")
    search_fields = ("feature_name", "employer__name")


@admin.register(CrisisHotline)
class CrisisHotlineAdmin(admin.ModelAdmin):
    list_display = ("employer", "contact_number", "description")
    search_fields = ("employer__name", "contact_number")

@admin.register(HotlineActivity)
class HotlineActivityAdmin(admin.ModelAdmin):
    list_display = ("employer", "call_count", "spike_percentage", "recorded_at")
    list_filter = ("recorded_at",)
    search_fields = ("employer__name",)


@admin.register(RecentActivity)
class RecentActivityAdmin(admin.ModelAdmin):
    list_display = ("employer", "activity_type", "details", "timestamp", "is_important")
    list_filter = ("is_important", "timestamp")
    search_fields = ("employer__name", "activity_type", "details")"""