from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator

# --- User & Authentication ---
class User(AbstractUser):
    ROLE_CHOICES = (
        ('systemadmin', 'System Admin'),
        ('employer', 'Employer'),
        ('employee', 'Employee'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='employee')
    onboarding_completed = models.BooleanField(default=False)
    is_suspended = models.BooleanField(default=False)
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=255, blank=True, null=True)
    avatar = models.ImageField(upload_to="avatars/", blank=True, null=True)
    is_suspended = models.BooleanField(default=False)
    mfa_enabled = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.username} ({self.role})"



class Organization(models.Model):
    name = models.CharField(max_length=255, unique=True)
    joined_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return str(self.name)

    class Meta:
        ordering = ['-joined_date']


class Client(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="clients")
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    joined_date = models.DateTimeField(auto_now_add=True)
    last_active = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.organization.name}"

    class Meta:
        ordering = ['-joined_date']



class AuthenticationEvent(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=50)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)


class AdminAction(models.Model):
    performed_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="admin_actions")
    target_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="targeted_actions")
    action_type = models.CharField(max_length=50)
    reason = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)


class SystemSetting(models.Model):
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    is_active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)


class FeatureFlag(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)


class SystemStatus(models.Model):
    is_in_maintenance = models.BooleanField(default=False)
    message = models.TextField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)



class SelfAssessment(models.Model):
    ASSESSMENT_TYPES = (
        ("GAD-7", "Anxiety"),
        ("PHQ-9", "Depression"),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="assessments")
    assessment_type = models.CharField(max_length=10, choices=ASSESSMENT_TYPES)
    score = models.PositiveIntegerField()
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-submitted_at']


class MoodCheckIn(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="mood_checkins")
    mood = models.CharField(max_length=50)
    note = models.TextField(blank=True, null=True)
    checked_in_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-checked_in_at']


class SelfHelpResource(models.Model):
    RESOURCE_TYPES = (
        ("Meditation", "Meditation"),
        ("CBT", "CBT Exercise"),
        ("Article", "Article"),
        ("Prompt", "Journaling Prompt"),
    )
    title = models.CharField(max_length=255)
    resource_type = models.CharField(max_length=50, choices=RESOURCE_TYPES)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)


class ChatbotInteraction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="chatbot_logs")
    message = models.TextField()
    response = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    escalated = models.BooleanField(default=False)



class UserBadge(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="badges")
    badge_name = models.CharField(max_length=100)
    awarded_on = models.DateTimeField(auto_now_add=True)


class EngagementStreak(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="streaks")
    streak_count = models.PositiveIntegerField(default=0)
    last_active_date = models.DateTimeField(blank=True, null=True)


# --- Employer Analytics ---
class AnalyticsSnapshot(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="analytics")
    date = models.DateField()
    active_users = models.PositiveIntegerField()
    average_stress_score = models.DecimalField(max_digits=5, decimal_places=2)
    most_used_feature = models.CharField(max_length=100)

class CrisisHotline(models.Model):
    country = models.CharField(max_length=100)
    region = models.CharField(max_length=100, blank=True, null=True)
    hotline_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)



class AIManagement(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="managements")
    title = models.CharField(max_length=255)
    description = models.TextField()
    effectiveness = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} - {self.organization.name}"

    class Meta:
        ordering = ['-created_at']


class HotlineActivity(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="hotline_activities")
    call_count = models.PositiveIntegerField(default=0)
    spike_percentage = models.DecimalField(max_digits=5, decimal_places=2, validators=[MinValueValidator(0), MaxValueValidator(100)])
    recorded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Hotline Activity - {self.organization.name} ({self.recorded_at})"

    class Meta:
        ordering = ['-recorded_at']
        verbose_name_plural = "Hotline Activities"


class ClientEngagement(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="engagements")
    engagement_rate = models.DecimalField(max_digits=5, decimal_places=2, validators=[MinValueValidator(0), MaxValueValidator(100)])
    month = models.DateField()
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.organization.name} - {self.month}"

    class Meta:
        ordering = ['-month']
        unique_together = ['organization', 'month']


class Subscription(models.Model):
    PLAN_CHOICES = (
        ("Free", "Free"),
        ("Premium", "Premium"),
    )
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="subscriptions")
    plan = models.CharField(max_length=50, choices=PLAN_CHOICES, default="Free")
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.organization.name} - {self.plan}"

    class Meta:
        ordering = ['-start_date']


class RecentActivity(models.Model):
    ACTIVITY_TYPES = (
        ("New Organization", "New Organization"),
        ("AI Management", "AI Management"),
        ("Hotline Activity", "Hotline Activity"),
        ("Client Engagement", "Client Engagement"),
        ("Subscription", "Subscription"),
    )
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="activities")
    activity_type = models.CharField(max_length=50, choices=ACTIVITY_TYPES)
    details = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_important = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.activity_type} - {self.organization.name}"

    class Meta:
        ordering = ['-timestamp']
        verbose_name_plural = "Recent Activities"
