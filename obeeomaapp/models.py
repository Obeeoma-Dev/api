from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth.models import User
from django.conf import settings

User = settings.AUTH_USER_MODEL

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

    def __str__(self):
        return f"{self.username} ({self.role})"


class Employer(models.Model):
    name = models.CharField(max_length=255, unique=True)
    joined_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return str(self.name)

    class Meta:
        ordering = ['-joined_date']


class Employee(models.Model):
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="employees")
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    joined_date = models.DateTimeField(auto_now_add=True)
    last_active = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.employer.name}"

    class Meta:
        ordering = ['-joined_date']


class AuthenticationEvent(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=50)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)


class AdminAction(models.Model):
    performed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="admin_actions")
    target_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="targeted_actions")
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
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="assessments")
    assessment_type = models.CharField(max_length=10, choices=ASSESSMENT_TYPES)
    score = models.PositiveIntegerField()
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-submitted_at']


class MoodCheckIn(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="mood_checkins")
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE, null=True, blank=True, related_name="mood_checkins_employee")
    mood = models.CharField(max_length=50)
    note = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
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
    resource_type = models.CharField(max_length=50, choices=RESOURCE_TYPES, blank=True, null=True)
    category = models.CharField(max_length=50, blank=True, null=True)  # meditation, journaling, CBT
    content = models.TextField()
    is_premium = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class ChatbotInteraction(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="chatbot_logs")
    message = models.TextField()
    response = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    escalated = models.BooleanField(default=False)


class UserBadge(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="badges")
    badge_name = models.CharField(max_length=100)
    awarded_on = models.DateTimeField(auto_now_add=True)


class EngagementStreak(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="streaks")
    streak_count = models.PositiveIntegerField(default=0)
    last_active_date = models.DateTimeField(blank=True, null=True)


class AnalyticsSnapshot(models.Model):
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="analytics")
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
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="managements")
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
        return f"{self.title} - {self.employer.name}"

    class Meta:
        ordering = ['-created_at']


class HotlineActivity(models.Model):
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="hotline_activities")
    call_count = models.PositiveIntegerField(default=0)
    spike_percentage = models.DecimalField(max_digits=5, decimal_places=2, validators=[MinValueValidator(0), MaxValueValidator(100)])
    recorded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Hotline Activity - {self.employer.name} ({self.recorded_at})"

    class Meta:
        ordering = ['-recorded_at']
        verbose_name_plural = "Hotline Activities"


class EmployeeEngagement(models.Model):
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="engagements")
    engagement_rate = models.DecimalField(max_digits=5, decimal_places=2, validators=[MinValueValidator(0), MaxValueValidator(100)])
    month = models.DateField()
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.employer.name} - {self.month}"

    class Meta:
        ordering = ['-month']
        unique_together = ['employer', 'month']


class Subscription(models.Model):
    PLAN_CHOICES = (
        ("Free", "Free"),
        ("Premium", "Premium"),
    )
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="subscriptions")
    plan = models.CharField(max_length=50, choices=PLAN_CHOICES, default="Free")
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.employer.name} - {self.plan}"

    class Meta:
        ordering = ['-start_date']


class RecentActivity(models.Model):
    ACTIVITY_TYPES = (
        ("New Employer", "New Employer"),
        ("AI Management", "AI Management"),
        ("Hotline Activity", "Hotline Activity"),
        ("Employee Engagement", "Employee Engagement"),
        ("Subscription", "Subscription"),
    )
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="activities")
    activity_type = models.CharField(max_length=50, choices=ACTIVITY_TYPES)
    details = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_important = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.activity_type} - {self.employer.name}"

    class Meta:
        ordering = ['-timestamp']
        verbose_name_plural = "Recent Activities"


# --- Employee Wellbeing ---

class EmployeeProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    organization = models.CharField(max_length=100)
    role = models.CharField(max_length=50)
    joined_on = models.DateField(auto_now_add=True)
    subscription_tier = models.CharField(max_length=20, choices=[('freemium', 'Freemium'), ('premium', 'Premium')])
    is_premium_active = models.BooleanField(default=False)
    is_anonymous = models.BooleanField(default=False)
    receive_notifications = models.BooleanField(default=True)
    current_wellness_status = models.CharField(max_length=50, blank=True)


class AvatarProfile(models.Model):
    employee = models.OneToOneField(EmployeeProfile, on_delete=models.CASCADE)
    style = models.CharField(max_length=50)
    color_theme = models.CharField(max_length=30)
    accessory = models.CharField(max_length=50, blank=True)


class WellnessHub(models.Model):
    employee = models.OneToOneField(EmployeeProfile, on_delete=models.CASCADE, related_name="wellness_hub")
    last_checkin_date = models.DateField(blank=True, null=True)
    last_checkin_mood = models.CharField(
        max_length=20,
        choices=[("happy", "Happy"), ("sad", "Sad"), ("stressed", "Stressed"),
                 ("anxious", "Anxious"), ("neutral", "Neutral")],
        blank=True,
        null=True
    )
    mood_logs = models.JSONField(default=list, blank=True)
    mood_insights = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Wellness Hub - {self.employee.user.username}"


class AssessmentResult(models.Model):
    employee = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE)
    type = models.CharField(max_length=20)  
    score = models.IntegerField()
    submitted_on = models.DateTimeField(auto_now_add=True)


class EducationalResource(models.Model):
    title = models.CharField(max_length=100)
    type = models.CharField(max_length=20)  # article, podcast, video
    url = models.URLField()
    description = models.TextField()


class CrisisTrigger(models.Model):
    employee = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE)
    detected_phrase = models.CharField(max_length=255)
    triggered_on = models.DateTimeField(auto_now_add=True)
    escalated = models.BooleanField(default=False)


class Notification(models.Model):
    employee = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE)
    message = models.CharField(max_length=255)
    sent_on = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)


class EngagementTracker(models.Model):
    employee = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE)
    streak_days = models.IntegerField(default=0)
    badges = models.CharField(max_length=255, blank=True)


class Feedback(models.Model):
    employee = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE)
    rating = models.IntegerField()
    comment = models.TextField()
    submitted_on = models.DateTimeField(auto_now_add=True)


class ChatSession(models.Model):
    employee = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE, related_name="chat_sessions")
    started_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)


class ChatMessage(models.Model):
    ROLE_CHOICES = [
        ("user", "User"),
        ("ai", "AI Assistant (Sana)"),
        ("system", "System")
    ]
    session = models.ForeignKey(ChatSession, on_delete=models.CASCADE, related_name="messages")
    sender = models.CharField(max_length=10, choices=ROLE_CHOICES)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)


class RecommendationLog(models.Model):
    employee = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE)
    resource = models.ForeignKey(SelfHelpResource, on_delete=models.SET_NULL, null=True, blank=True)
    recommended_on = models.DateTimeField(auto_now_add=True)
    clicked = models.BooleanField(default=False)



class MentalHealthAssessment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mental_health_assessments')
    assessment_type = models.CharField(max_length=10, choices=[
        ('GAD-7', 'GAD-7 (Anxiety)'),
        ('PHQ-9', 'PHQ-9 (Depression)'),
        ('BOTH', 'Both Assessments')
    ])
    gad7_scores = models.JSONField(default=list, blank=True)  # Store answers to 7 GAD-7 questions
    phq9_scores = models.JSONField(default=list, blank=True)  # Store answers to 9 PHQ-9 questions
    gad7_total = models.PositiveIntegerField(default=0)
    phq9_total = models.PositiveIntegerField(default=0)
    gad7_severity = models.CharField(max_length=20, blank=True)
    phq9_severity = models.CharField(max_length=20, blank=True)
    assessment_date = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-assessment_date']
        
    def __str__(self):
        return f'Assessment for {self.user.username} on {self.assessment_date}'
    
    def calculate_gad7_severity(self):
        """Calculate GAD-7 severity level based on total score"""
        if self.gad7_total <= 4:
            return "Minimal anxiety"
        elif self.gad7_total <= 9:
            return "Mild anxiety"
        elif self.gad7_total <= 14:
            return "Moderate anxiety"
        else:
            return "Severe anxiety"
    
    def calculate_phq9_severity(self):
        """Calculate PHQ-9 severity level based on total score"""
        if self.phq9_total <= 4:
            return "Minimal depression"
        elif self.phq9_total <= 9:
            return "Mild depression"
        elif self.phq9_total <= 14:
            return "Moderate depression"
        elif self.phq9_total <= 19:
            return "Moderately severe depression"
        else:
            return "Severe depression"
    
    def save(self, *args, **kwargs):
        # Calculate totals and severities before saving
        if self.gad7_scores:
            self.gad7_total = sum(self.gad7_scores)
            self.gad7_severity = self.calculate_gad7_severity()
        
        if self.phq9_scores:
            self.phq9_total = sum(self.phq9_scores)
            self.phq9_severity = self.calculate_phq9_severity()
            
        super().save(*args, **kwargs)



