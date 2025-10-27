from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
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
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('suspended', 'Suspended'),
    ]
    
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="employees")
    department = models.ForeignKey('Department', on_delete=models.SET_NULL, null=True, blank=True, related_name="employees")
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    joined_date = models.DateTimeField(auto_now_add=True)
    last_active = models.DateTimeField(auto_now=True)
    avatar = models.ImageField(upload_to='employee_avatars/', blank=True, null=True)

    def _str_(self):
        return f"{self.name} - {self.employer.name}"

    class Meta:
        ordering = ['-joined_date']


# --- Invitations ---
class EmployeeInvitation(models.Model):
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="invitations")
    email = models.EmailField()
    token = models.CharField(max_length=64, unique=True)
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    message = models.TextField(blank=True)
    expires_at = models.DateTimeField()
    accepted = models.BooleanField(default=False)
    accepted_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Invite {self.email} -> {self.employer.name}"

    class Meta:
        indexes = [models.Index(fields=["token"])]


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
    PLAN_CHOICES = [
        ("starter", "Starter Plan"),
        ("enterprise", "Enterprise Plan"),
        ("enterprise_plus", "Enterprise Plus Plan"),
    ]
    
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="subscriptions")
    plan = models.CharField(max_length=50, choices=PLAN_CHOICES, default="starter")
    plan_details = models.ForeignKey('SubscriptionPlan', on_delete=models.SET_NULL, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    seats = models.PositiveIntegerField(default=5)
    used_seats = models.PositiveIntegerField(default=0)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    renewal_date = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    payment_method = models.ForeignKey('PaymentMethod', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.employer.name} - {self.plan}"

    @property
    def available_seats(self):
        return self.seats - self.used_seats

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
    employee = models.OneToOneField('EmployeeProfile', on_delete=models.CASCADE)
    style = models.CharField(max_length=50)
    color_theme = models.CharField(max_length=30)
    accessory = models.CharField(max_length=50, blank=True)


class WellnessHub(models.Model):
    employee = models.OneToOneField('EmployeeProfile', on_delete=models.CASCADE, related_name="wellness_hub")
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
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
    type = models.CharField(max_length=20)  
    score = models.IntegerField()
    submitted_on = models.DateTimeField(auto_now_add=True)


class EducationalResource(models.Model):
    title = models.CharField(max_length=100)
    type = models.CharField(max_length=20)  # article, podcast, video
    url = models.URLField()
    description = models.TextField()


class CrisisTrigger(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
    detected_phrase = models.CharField(max_length=255)
    triggered_on = models.DateTimeField(auto_now_add=True)
    escalated = models.BooleanField(default=False)


class Notification(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
    message = models.CharField(max_length=255)
    sent_on = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)


class EngagementTracker(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
    streak_days = models.IntegerField(default=0)
    badges = models.CharField(max_length=255, blank=True)


class Feedback(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
    rating = models.IntegerField()
    comment = models.TextField()
    submitted_on = models.DateTimeField(auto_now_add=True)

class Progress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField()
    mood_score = models.IntegerField()
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} - {self.date}"
    
class ChatSession(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE, related_name="chat_sessions")
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
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
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


# Employers Models.
class Department(models.Model):
    """Departments within an employer (e.g., HR, Marketing, Engineering)."""
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="departments")
    name = models.CharField(max_length=100)
    at_risk = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.employer.name}"

    class Meta:
        ordering = ['name']



class Assessment(models.Model):
    """Each assessment (e.g., GAD-7 or PHQ-9) completed by an employee."""
    ASSESSMENT_TYPES = [
        ("GAD-7", "Generalized Anxiety Disorder (GAD-7)"),
        ("PHQ-9", "Patient Health Questionnaire (PHQ-9)"),
    ]

    employee = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name="assessments")
    department = models.ForeignKey('Department', on_delete=models.SET_NULL, null=True, blank=True)
    assessment_type = models.CharField(max_length=50, choices=ASSESSMENT_TYPES)
    score = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.employee.user.username} - {self.assessment_type} ({self.score})"

    class Meta:
        ordering = ["-created_at"]


class PasswordResetToken(models.Model):
    """Model to store password reset tokens"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="password_reset_tokens")
    token = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=6)  # 6-digit verification code
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Password reset token for {self.user.email}"

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["token"]), models.Index(fields=["code"])]

    def is_expired(self):
        from django.utils import timezone
        return timezone.now() > self.expires_at

    def mark_as_used(self):
        from django.utils import timezone
        self.is_used = True
        self.used_at = timezone.now()
        self.save()

class ResourceCategory(models.Model):
    """Categories for organizing mental health resources (e.g., Stress Management, Anxiety, Depression)"""
    name = models.CharField(max_length=100, help_text="e.g., Stress Management, Anxiety Relief, Sleep Help")
    description = models.TextField(blank=True, help_text="Brief description of what this category covers")
    icon = models.CharField(max_length=50, blank=True, help_text="Emoji or icon name")
    color_code = models.CharField(max_length=7, default="#667eea", help_text="Hex color for UI theming")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Resource Category"
        verbose_name_plural = "Resource Categories"
        ordering = ['name']
    
    def __str__(self):
        return f"{self.icon} {self.name}" if self.icon else self.name


# Enhanced Models for Dashboard Functionality

class OrganizationSettings(models.Model):
    """Organization-level settings and preferences"""
    employer = models.OneToOneField(Employer, on_delete=models.CASCADE, related_name="settings")
    organization_name = models.CharField(max_length=255, default="Admin User")
    email_address = models.EmailField(default="admin@example.com")
    anonymize_data = models.BooleanField(default=True)
    enhanced_privacy = models.BooleanField(default=False)
    data_retention_days = models.PositiveIntegerField(default=90)
    weekly_reports = models.BooleanField(default=True)
    browser_notifications = models.BooleanField(default=True)
    report_generation_notifications = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Settings for {self.employer.name}"


class SubscriptionPlan(models.Model):
    """Available subscription plans"""
    PLAN_CHOICES = [
        ('starter', 'Starter Plan'),
        ('enterprise', 'Enterprise Plan'),
        ('enterprise_plus', 'Enterprise Plus Plan'),
    ]
    
    name = models.CharField(max_length=50, choices=PLAN_CHOICES)
    display_name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    seats = models.PositiveIntegerField()
    description = models.TextField()
    features = models.JSONField(default=list)  # List of features
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.display_name} - ${self.price}/month"

    class Meta:
        ordering = ['price']


class BillingHistory(models.Model):
    """Billing history for organizations"""
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="billing_history")
    invoice_number = models.CharField(max_length=50, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    plan_name = models.CharField(max_length=100)
    billing_date = models.DateField()
    status = models.CharField(max_length=20, choices=[
        ('paid', 'Paid'),
        ('pending', 'Pending'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled')
    ], default='paid')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.employer.name} - {self.invoice_number}"

    class Meta:
        ordering = ['-billing_date']


class PaymentMethod(models.Model):
    """Payment methods for organizations"""
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="payment_methods")
    card_type = models.CharField(max_length=20)  # Visa, Mastercard, etc.
    last_four_digits = models.CharField(max_length=4)
    expiry_month = models.PositiveIntegerField()
    expiry_year = models.PositiveIntegerField()
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.card_type} ending in {self.last_four_digits}"

    class Meta:
        ordering = ['-is_default', '-created_at']


class WellnessTest(models.Model):
    """Wellness tests completed by employees"""
    TEST_TYPES = [
        ('wellbeing_check', 'Well-being Check'),
        ('burnout_risk', 'Burnout Risk'),
        ('stress_assessment', 'Stress Assessment'),
    ]
    
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name="wellness_tests")
    department = models.ForeignKey('Department', on_delete=models.SET_NULL, null=True, blank=True)
    test_type = models.CharField(max_length=50, choices=TEST_TYPES)
    score = models.PositiveIntegerField()
    completed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.employee.name} - {self.test_type}"

    class Meta:
        ordering = ['-completed_at']


class ResourceEngagement(models.Model):
    """Track employee engagement with wellness resources"""
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name="resource_engagements")
    resource_type = models.CharField(max_length=50)
    resource_id = models.PositiveIntegerField()
    completed = models.BooleanField(default=False)
    engagement_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.employee.name} - {self.resource_type}"

    class Meta:
        ordering = ['-engagement_date']


class CommonIssue(models.Model):
    """Common issues identified in the organization"""
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="common_issues")
    issue_name = models.CharField(max_length=255)
    description = models.TextField()
    affected_departments = models.ManyToManyField(Department, blank=True)
    severity = models.CharField(max_length=20, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ], default='medium')
    identified_at = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.issue_name} - {self.employer.name}"

    class Meta:
        ordering = ['-identified_at']


class ChatEngagement(models.Model):
    """Track chat engagement metrics"""
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="chat_engagements")
    test_type = models.CharField(max_length=50)
    engagement_count = models.PositiveIntegerField(default=0)
    recorded_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.employer.name} - {self.test_type}"

    class Meta:
        ordering = ['-recorded_date']


class DepartmentContribution(models.Model):
    """Track contributions by department"""
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="department_contributions")
    department = models.ForeignKey('Department', on_delete=models.CASCADE)
    contribution_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    recorded_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.department.name} - {self.contribution_percentage}%"

    class Meta:
        ordering = ['-contribution_percentage']


class OrganizationActivity(models.Model):
    """Recent activities in the organization"""
    ACTIVITY_TYPES = [
        ('wellness_test_completed', 'Wellness Test Completed'),
        ('monthly_assessment', 'Monthly Assessment'),
        ('resource_added', 'Resource Added'),
        ('employee_joined', 'Employee Joined'),
        ('department_created', 'Department Created'),
    ]
    
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="organization_activities")
    activity_type = models.CharField(max_length=50, choices=ACTIVITY_TYPES)
    description = models.TextField()
    department = models.ForeignKey('Department', on_delete=models.SET_NULL, null=True, blank=True)
    employee = models.ForeignKey(Employee, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.activity_type} - {self.employer.name}"

    class Meta:
        ordering = ['-created_at']


# System Admin Models

class PlatformMetrics(models.Model):
    """Platform-wide metrics for system admin dashboard"""
    total_organizations = models.PositiveIntegerField(default=0)
    total_clients = models.PositiveIntegerField(default=0)
    monthly_revenue = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    hotline_calls_today = models.PositiveIntegerField(default=0)
    organizations_this_month = models.PositiveIntegerField(default=0)
    clients_this_month = models.PositiveIntegerField(default=0)
    revenue_growth_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    hotline_growth_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    recorded_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"Platform Metrics - {self.recorded_date}"

    class Meta:
        ordering = ['-recorded_date']


class PlatformUsage(models.Model):
    """Platform usage tracking for charts"""
    week_number = models.PositiveIntegerField()
    usage_count = models.PositiveIntegerField()
    recorded_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"Week {self.week_number} - {self.usage_count}"

    class Meta:
        ordering = ['week_number']


class SubscriptionRevenue(models.Model):
    """Monthly subscription revenue tracking"""
    month = models.CharField(max_length=10)  # Jan, Feb, etc.
    revenue = models.DecimalField(max_digits=12, decimal_places=2)
    year = models.PositiveIntegerField()
    recorded_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.month} {self.year} - ${self.revenue}"

    class Meta:
        ordering = ['year', 'month']


class SystemActivity(models.Model):
    """System-wide activities for admin dashboard"""
    ACTIVITY_TYPES = [
        ('new_organization', 'New Organization'),
        ('ai_recommendation', 'AI Recommendation'),
        ('hotline_activity', 'Hotline Activity'),
        ('patient_engagement', 'Patient Engagement'),
        ('subscription', 'Subscription'),
    ]
    
    activity_type = models.CharField(max_length=50, choices=ACTIVITY_TYPES)
    details = models.TextField()
    organization = models.ForeignKey(Employer, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.activity_type} - {self.created_at}"

    class Meta:
        ordering = ['-created_at']


class HotlineCall(models.Model):
    """Hotline calls for system admin tracking"""
    URGENCY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('resolved', 'Resolved'),
        ('referred', 'Referred'),
        ('escalated', 'Escalated'),
        ('pending', 'Pending'),
    ]
    
    REASON_CHOICES = [
        ('anxiety', 'Anxiety'),
        ('depression', 'Depression'),
        ('crisis', 'Crisis'),
        ('information', 'Information'),
        ('other', 'Other'),
    ]
    
    call_id = models.CharField(max_length=20, unique=True)
    duration_minutes = models.PositiveIntegerField()
    reason = models.CharField(max_length=20, choices=REASON_CHOICES)
    urgency = models.CharField(max_length=20, choices=URGENCY_LEVELS)
    operator_name = models.CharField(max_length=100)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    organization = models.ForeignKey(Employer, on_delete=models.SET_NULL, null=True, blank=True)
    call_date = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Call {self.call_id} - {self.reason}"

    class Meta:
        ordering = ['-call_date']


class AIResource(models.Model):
    """AI-managed resources for effectiveness tracking"""
    RESOURCE_TYPES = [
        ('article', 'Article'),
        ('video', 'Video'),
        ('audio', 'Audio'),
        ('interactive', 'Interactive'),
        ('worksheet', 'Worksheet'),
    ]
    
    title = models.CharField(max_length=255)
    resource_type = models.CharField(max_length=20, choices=RESOURCE_TYPES)
    recommended_count = models.PositiveIntegerField(default=0)
    engagement_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    effectiveness_score = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    last_updated = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.title} - {self.resource_type}"

    class Meta:
        ordering = ['-effectiveness_score']


class ClientEngagement(models.Model):
    """Client engagement tracking for rewards system"""
    client_name = models.CharField(max_length=255)
    organization = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="client_engagements")
    sessions_completed = models.PositiveIntegerField(default=0)
    current_streak = models.PositiveIntegerField(default=0)
    total_points = models.PositiveIntegerField(default=0)
    engagement_level = models.CharField(max_length=20, choices=[
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ], default='medium')
    last_active = models.DateTimeField(auto_now=True)
    avatar_icon = models.CharField(max_length=50, default='trophy')  # trophy, star, clock

    def __str__(self):
        return f"{self.client_name} - {self.organization.name}"

    class Meta:
        ordering = ['-total_points']


class RewardProgram(models.Model):
    """Reward programs for client engagement"""
    name = models.CharField(max_length=255)
    points_required = models.PositiveIntegerField()
    redemption_count = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.points_required} points"

    class Meta:
        ordering = ['points_required']


"""class FeatureFlag(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    is_enabled = models.BooleanField(default=False)
    category = models.CharField(max_length=50, default='general')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def _str_(self):
        return f"{self.name} - {'Enabled' if self.is_enabled else 'Disabled'}"

    class Meta:
        ordering = ['category', 'name']"""


class SystemSettings(models.Model):
    """System-wide settings for admin"""
    setting_name = models.CharField(max_length=100, unique=True)
    setting_value = models.TextField()
    setting_type = models.CharField(max_length=50, choices=[
        ('string', 'String'),
        ('boolean', 'Boolean'),
        ('integer', 'Integer'),
        ('json', 'JSON'),
    ], default='string')
    description = models.TextField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.setting_name} - {self.setting_value}"

    class Meta:
        ordering = ['setting_name']


class Report(models.Model):
    """Generated reports for system admin"""
    REPORT_TYPES = [
        ('platform_usage', 'Platform Usage'),
        ('organization_performance', 'Organization Performance'),
        ('mental_health_trends', 'Mental Health Trends'),
        ('ai_effectiveness', 'AI Effectiveness'),
        ('hotline_activity', 'Hotline Activity'),
    ]
    
    FORMAT_CHOICES = [
        ('pdf', 'PDF'),
        ('excel', 'Excel'),
        ('csv', 'CSV'),
    ]
    
    title = models.CharField(max_length=255)
    report_type = models.CharField(max_length=50, choices=REPORT_TYPES)
    format = models.CharField(max_length=10, choices=FORMAT_CHOICES)
    file_size_mb = models.DecimalField(max_digits=5, decimal_places=2)
    generated_date = models.DateTimeField(auto_now_add=True)
    file_path = models.CharField(max_length=500, blank=True, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.title} - {self.format.upper()}"

    class Meta:
        ordering = ['-generated_date']


# models.py


class ResourceCategory(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=50, blank=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name_plural = "Resource Categories"

class EducationalVideo(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    youtube_url = models.URLField()
    thumbnail = models.URLField(blank=True, null=True)
    resource_category = models.ForeignKey(ResourceCategory, on_delete=models.CASCADE, related_name='educational_videos')
    duration = models.CharField(max_length=20, blank=True)
    
    MOOD_CHOICES = [
        ('anxiety', 'Anxiety Relief'),
        ('depression', 'Depression Support'),
        ('stress', 'Stress Management'),
        ('mindfulness', 'Mindfulness & Meditation'),
        ('self_esteem', 'Self-Esteem Building'),
        ('coping', 'Coping Skills'),
        ('sleep', 'Sleep Improvement'),
        ('anger', 'Anger Management'),
        ('grief', 'Grief & Loss'),
        ('general', 'General Wellness'),
    ]
    
    INTENSITY_LEVEL = [
        (1, 'Gentle - For difficult moments'),
        (2, 'Moderate - Daily practice'),
        (3, 'Deep - Intensive work'),
    ]
    
    target_mood = models.CharField(max_length=50, choices=MOOD_CHOICES, default='general')
    intensity_level = models.IntegerField(choices=INTENSITY_LEVEL, default=1)
    crisis_support_text = models.TextField(blank=True)
    
    views_count = models.IntegerField(default=0)
    helpful_count = models.IntegerField(default=0)
    saved_count = models.IntegerField(default=0)
    
    is_professionally_reviewed = models.BooleanField(default=False)
    reviewed_by = models.CharField(max_length=100, blank=True)
    review_date = models.DateField(blank=True, null=True)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Educational Video"
        verbose_name_plural = "Educational Videos"
        ordering = ['-created_at']
    
    def __str__(self):
        return self.title

# ADD THIS MODEL - UserVideoInteraction
class UserVideoInteraction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    video = models.ForeignKey(EducationalVideo, on_delete=models.CASCADE)
    
    MOOD_BEFORE = [
        (1, 'Very distressed'),
        (2, 'Somewhat distressed'),
        (3, 'Neutral'),
        (4, 'Somewhat calm'),
        (5, 'Very calm'),
    ]
    
    MOOD_AFTER = [
        (1, 'Much worse'),
        (2, 'Slightly worse'),
        (3, 'No change'),
        (4, 'Slightly better'),
        (5, 'Much better'),
    ]
    
    mood_before = models.IntegerField(choices=MOOD_BEFORE, blank=True, null=True)
    mood_after = models.IntegerField(choices=MOOD_AFTER, blank=True, null=True)
    watched_full_video = models.BooleanField(default=False)
    marked_helpful = models.BooleanField(default=False)
    saved_for_later = models.BooleanField(default=False)
    watched_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'video']
    
    def __str__(self):
        return f"{self.user.username} - {self.video.title}"        