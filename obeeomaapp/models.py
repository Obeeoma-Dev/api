from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.conf import settings
from django.contrib.auth.models import User
from django.utils.text import slugify
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

User = settings.AUTH_USER_MODEL
import pyotp
from cryptography.fernet import Fernet

#User and Authentication Models
class User(AbstractUser):
    ROLE_CHOICES = (
        ('systemadmin', 'Systemadmin'),
        ('organisation', 'Organisation'),
        ('employee', 'Employee'),
    )

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='employee')
    onboarding_completed = models.BooleanField(default=False)
    is_suspended = models.BooleanField(default=False)

    # These are the MFA-related fields
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=255, blank=True, null=True)

    avatar = models.ImageField(upload_to="avatars/", blank=True, null=True)
    email = models.EmailField(unique=True)

    def __str__(self):
        return f"{self.username} ({self.role})"

    # These are the MFA Utility Methods
    def generate_mfa_secret(self):
        """
        Create a new TOTP secret and encrypt it before saving.
        Called when the admin enables MFA.
        """
        raw_secret = pyotp.random_base32()
        fernet = Fernet(settings.FERNET_KEY)
        encrypted_secret = fernet.encrypt(raw_secret.encode()).decode()
        self.mfa_secret = encrypted_secret
        self.save(update_fields=["mfa_secret"])
        return raw_secret  # This helps in Returning the raw one for generating the QR

    def get_mfa_secret(self):
        """
        Decrypt the stored secret (for verification or QR generation).
        """
        if not self.mfa_secret:
            return None
        fernet = Fernet(settings.FERNET_KEY)
        return fernet.decrypt(self.mfa_secret.encode()).decode()

    def get_otpauth_url(self):
        """
        Generate the otpauth URL for use in Google Authenticator.
        """
        secret = self.get_mfa_secret()
        if not secret:
            return None
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=self.username,
            issuer_name="ObeeomaApp"
        )

    def verify_mfa_code(self, code):
        """
        Verify a 6-digit MFA code entered by the user.
        """
        secret = self.get_mfa_secret()
        if not secret:
            return False
        totp = pyotp.TOTP(secret)
        return totp.verify(code)

    

#MODELS FOR CREATING AN ORGANIZATION
class ContactPerson(models.Model):
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    role = models.CharField(max_length=100)
    email = models.EmailField()

    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.role}"

# --- Organization Model ---
class Organization(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='organizations', null=True, blank=True)
    organizationName = models.CharField(max_length=255)
    organisationSize = models.CharField(max_length=50)
    phoneNumber = models.CharField(max_length=20)
    companyEmail = models.EmailField(unique=True)
    Location = models.CharField(max_length=255)
    password = models.CharField(max_length=128)
    contactPerson = models.OneToOneField(ContactPerson, on_delete=models.CASCADE, related_name='organization', null=True, blank=True)

    def __str__(self):
        return self.organizationName

# MODELS FOR VERIFYING THE OTP
class PasswordResetOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        # OTP expires after 5 minutes
        return timezone.now() > self.created_at + timedelta(minutes=5)

    def __str__(self):
        return f"{self.user.username} - {self.code}"


# --- Employers Model. ---
class  Employer(models.Model):
    name = models.CharField(max_length=255, unique=True)
    joined_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return str(self.name)

    class Meta:
        ordering = ['-joined_date']

# Employees Models. 
class Employee(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('suspended', 'Suspended'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="employee_profile", null=True, blank=True)
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="employees")
    department = models.ForeignKey('Department', on_delete=models.SET_NULL, null=True, blank=True, related_name="employees")
    first_name = models.CharField(max_length=100, default='')
    last_name = models.CharField(max_length=100, default='')
    email = models.EmailField(unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    joined_date = models.DateTimeField(auto_now_add=True)
    last_active = models.DateTimeField(auto_now=True)
    avatar = models.ImageField(upload_to='employee_avatars/', blank=True, null=True)

    @property
    def name(self):
        return f"{self.first_name} {self.last_name}".strip() or self.email

    def __str__(self):
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
    expires_at = models.DateTimeField(blank=True, null=True)
    accepted = models.BooleanField(default=False)
    accepted_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Automatically set expires_at to 7 days from now if not set
        if not self.expires_at:
            from django.utils import timezone
            from datetime import timedelta
            self.expires_at = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Invite {self.email} -> {self.employer.name}"

    class Meta:
        indexes = [models.Index(fields=["token"])]

# --- System Admin Models ---
class AuthenticationEvent(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=50)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

# --- System Admin Models ---
class AdminAction(models.Model):
    performed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="admin_actions")
    target_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="targeted_actions")
    action_type = models.CharField(max_length=50)
    reason = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

# --- System Settings & Status ---
class SystemSetting(models.Model):
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    is_active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

# --- System Status ---
class SystemStatus(models.Model):
    is_in_maintenance = models.BooleanField(default=False)
    message = models.TextField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

# --- Dashboard Functionality Models ---
# Mental Health Assessments model.
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

# --- Employee Wellbeing Models ---
# Mood Tracking model.
class MoodTracking(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="mood_checkins")
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE, null=True, blank=True, related_name="mood_checkins_employee")
    mood = models.CharField(max_length=50, blank=True, null=True)
    note = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    checked_in_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-checked_in_at']

    def __str__(self):
        return f"{self.user.username} - {self.mood} ({self.checked_in_at.date()})"


# Self-Help Resources model.
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

# Chatbot Interactions model.
class ChatbotInteraction(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="chatbot_logs")
    message = models.TextField()
    response = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    escalated = models.BooleanField(default=False)

# Badges & Achievements model.
class UserBadge(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="badges")
    badge_name = models.CharField(max_length=100)
    awarded_on = models.DateTimeField(auto_now_add=True)

# Engagement Streaks model.
class EngagementStreak(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="streaks")
    streak_count = models.PositiveIntegerField(default=0)
    last_active_date = models.DateTimeField(blank=True, null=True)

# Analytics & Reporting model.
class AnalyticsSnapshot(models.Model):
    employer = models.ForeignKey(Employer, on_delete=models.CASCADE, related_name="analytics")
    date = models.DateField()
    active_users = models.PositiveIntegerField()
    average_stress_score = models.DecimalField(max_digits=5, decimal_places=2)
    most_used_feature = models.CharField(max_length=100)

# Crisis Hotline Information model.
class CrisisHotline(models.Model):
    country = models.CharField(max_length=100)
    region = models.CharField(max_length=100, blank=True, null=True)
    hotline_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
     
# Dashboard Models for Employers
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

# Hotline Activity model.
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





# Employee Engagement model.
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

# Subscriptions model.
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

# Recent activities model.
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

    def __str__(self):
        return f"{self.user.username} - {self.organization}"

# Avatar Customization model.
class AvatarProfile(models.Model):
    employee = models.OneToOneField('EmployeeProfile', on_delete=models.CASCADE)
    style = models.CharField(max_length=50)
    color_theme = models.CharField(max_length=30)
    accessory = models.CharField(max_length=50, blank=True)

    def __str__(self):
        return f"Avatar for {self.employee.user.username}"

# Wellness Hub model.
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



# Assessment Results model.
class AssessmentResult(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
    type = models.CharField(max_length=20)  
    score = models.IntegerField()
    submitted_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Assessment - {self.employee.user.username} - {self.type}"

# Crisis Triggers model.
class CrisisTrigger(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
    detected_phrase = models.CharField(max_length=255)
    triggered_on = models.DateTimeField(auto_now_add=True)
    escalated = models.BooleanField(default=False)

    def __str__(self):
        return f"Crisis Trigger - {self.employee.user.username}"

# Notifications model.
class Notification(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
    message = models.CharField(max_length=255, blank=True, null=True)
    content_type = models.CharField(max_length=50, blank=True, null=True)  
    object_id = models.PositiveIntegerField(blank=True, null=True)
    sent_on = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)

    def __str__(self):
        return f"Notification - {self.employee.user.username}"

# Engagement Tracker model.
class EngagementTracker(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
    streak_days = models.IntegerField(default=0)
    badges = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return f"Engagement - {self.employee.user.username}"

# Feedback model.
class Feedback(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
    rating = models.IntegerField()
    comment = models.TextField()
    submitted_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Feedback - {self.employee.user.username}"

# Progress Tracking model.
class Progress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField()
    mood_score = models.IntegerField()
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} - {self.date}"
 # Chat Sessions model.   
class ChatSession(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE, related_name="chat_sessions")
    started_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Chat Session - {self.employee.user.username}"

# Chat Messages model.
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

    def __str__(self):
        return f"Message - {self.session.employee.user.username}"

# Recommendation Logs model.
class RecommendationLog(models.Model):
    employee = models.ForeignKey('EmployeeProfile', on_delete=models.CASCADE)
    resource = models.ForeignKey(SelfHelpResource, on_delete=models.SET_NULL, null=True, blank=True)
    recommended_on = models.DateTimeField(auto_now_add=True)
    clicked = models.BooleanField(default=False)

    def __str__(self):
        return f"Recommendation - {self.employee.user.username}"


# Mental Health Assessments model.
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
#-- Departments Model. --
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


#-- Assessments Model. --
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
        return f"{self.employee.name} - {self.assessment_type} ({self.score})"

    class Meta:
        ordering = ["-created_at"]

#-- Password Reset Tokens Model. --
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

# Enhanced Models for Dashboard Functionality
#-- Organization Settings Model. --
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

#-- Subscription Plans Model. --
class SubscriptionPlan(models.Model):
    """Available subscription plans"""
    PLAN_CHOICES = [
        ('starter', 'Starter Plan'),
        ('enterprise', 'Enterprise Plan'),
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

#-- Billing History Model. --
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

#-- Payment Methods Model. --
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

#-- Wellness Tests Model. --
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



#-- Resource Engagement Model. --
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

#-- Common Issues Model. --
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

#-- Chat Engagement Model. --
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

#-- Department Contribution Model. --
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

#-- Organization Activity Model. --
class OrganizationActivity(models.Model):
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
#-- Platform Metrics Model. --
class PlatformMetrics(models.Model):
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

#-- Platform Usage Model. --
class PlatformUsage(models.Model):
    week_number = models.PositiveIntegerField()
    usage_count = models.PositiveIntegerField()
    recorded_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"Week {self.week_number} - {self.usage_count}"

    class Meta:
        ordering = ['week_number']
#-- Subscription Revenue Model. --
class SubscriptionRevenue(models.Model):
    month = models.CharField(max_length=10)  # Jan, Feb, etc.
    revenue = models.DecimalField(max_digits=12, decimal_places=2)
    year = models.PositiveIntegerField()
    recorded_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.month} {self.year} - ${self.revenue}"

    class Meta:
        ordering = ['year', 'month']

#-- System Activity Model. --
class SystemActivity(models.Model):
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

#Hotline Call Model. --
class HotlineCall(models.Model):
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

#-- AI Resource Model. --
class AIResource(models.Model):
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

#-- Client Engagement Model. --
class ClientEngagement(models.Model):
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

#-- Reward Programs Model. --
class RewardProgram(models.Model):
    name = models.CharField(max_length=255)
    points_required = models.PositiveIntegerField()
    redemption_count = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.points_required} points"

    class Meta:
        ordering = ['points_required']

#-- System Settings Model. --
class SystemSettings(models.Model):
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

#-- Reports Model. --
class Report(models.Model):
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

# --Educational Resources Models--
class EducationalResource(models.Model):
    TYPE_CHOICES = [
        ('pdf', 'PDF'),
        ('audio', 'Audio'),
        ('video', 'Video'),
        ('article', 'Article'),
        ('meditation technique', 'Meditation Technique'),
    ]
    icon = models.CharField(max_length=50, blank=True)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    resource_type = models.CharField(max_length=20, choices=TYPE_CHOICES, null=True, blank=True)
    file = models.FileField(upload_to='educational_files/', null=True, blank=True)
    thumbnail = models.ImageField(upload_to='thumbnails/', blank=True, null=True)
    file_size = models.CharField(max_length=20, blank=True, null=True)
    uploaded_by = models.ForeignKey(Employee, on_delete=models.SET_NULL, null=True, related_name='uploaded_resources')
    uploaded_at = models.DateTimeField(auto_now_add=True)  # Remove default
    is_public = models.BooleanField(default=True)
    download_count = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'resources'
        verbose_name = " Educational Resource"
        verbose_name_plural = " Educational Resources"
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return self.title

#-- Video Model. --
class Video(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField(help_text="What will users learn?")
    youtube_url = models.URLField(help_text="YouTube video URL")
    category = models.ForeignKey(EducationalResource,on_delete=models.SET_NULL,null=True,blank=True,related_name='videos')
    # thumbnail = models.URLField(blank=True, null=True)
    duration = models.CharField(max_length=20, blank=True, help_text="e.g., 10:30")
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
        ('sad', 'Sadness Support'),
    ]
    views = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  
    target_mood = models.CharField(max_length=50, choices=MOOD_CHOICES, default='general')
    is_professionally_reviewed = models.BooleanField(default=False)
    reviewed_by = models.CharField(max_length=100, blank=True)
    review_date = models.DateField(blank=True, null=True)
    crisis_support_text = models.TextField(blank=True)
    
    views_count = models.IntegerField(default=0)
    helpful_count = models.IntegerField(default=0)
    saved_count = models.IntegerField(default=0)
    class Meta:
        ordering = ['-created_at']
        verbose_name = " Video"
        verbose_name_plural = " Videos"
    
    def __str__(self):
        return self.title

#-- Audio Model. --
class Audio(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField(help_text="What does this audio help with?")
    audio_file = models.FileField(upload_to='audios/', blank=True, null=True)
    audio_url = models.URLField(blank=True, null=True, help_text="External audio URL")
    category = models.ForeignKey(EducationalResource, on_delete=models.SET_NULL, null=True, blank=True, related_name='audios')

    duration = models.CharField(max_length=20, blank=True)
    plays = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  

    
    class Meta:
        ordering = ['-created_at']
        verbose_name = " Audio"
        verbose_name_plural = " Audios"
    
    def __str__(self):
        return self.title

#-- Article Model. --
class Article(models.Model):
    title = models.CharField(max_length=200)
    slug = models.SlugField(unique=True, max_length=250, blank=True)
    content = models.TextField()
    excerpt = models.TextField(max_length=500, blank=True, help_text="Short summary")
    author = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    category = models.ForeignKey(EducationalResource, on_delete=models.CASCADE, related_name='articles')
    featured_image = models.ImageField(upload_to='articles/', blank=True, null=True)
    reading_time = models.IntegerField(default=5, help_text="Minutes to read")
    views = models.IntegerField(default=0)
    is_published = models.BooleanField(default=True)
    published_date = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)  

    
    class Meta:
        
        verbose_name_plural = " Articles"
        ordering = ['-published_date']
        verbose_name = " Article"
    
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.title

#-- Meditation Technique Model. --
class MeditationTechnique(models.Model):
    DIFFICULTY_CHOICES = [
        ('beginner', 'Beginner'),
        ('intermediate', 'Intermediate'),
        ('advanced', 'Advanced'),
    ]
    
    title = models.CharField(max_length=200)
    description = models.TextField(help_text="what you want to achieve with this meditation")
    instructions = models.TextField(help_text="Step-by-step guide")
    duration = models.IntegerField(help_text="Duration in minutes")
    difficulty = models.CharField(max_length=20, choices=DIFFICULTY_CHOICES, default='beginner')
    category = models.ForeignKey(EducationalResource, on_delete=models.CASCADE, related_name='meditations')
    benefits = models.TextField(blank=True)
    image = models.ImageField(upload_to='meditation/', blank=True, null=True)
    times_practiced = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  #  Remove default
  
    class Meta:
        ordering = ['difficulty', 'title']
        verbose_name_plural = "Guided Meditations"
        verbose_name = "Meditation Technique"
    
    def __str__(self):
        return f"{self.title} ({self.get_difficulty_display()})"

#-- Saved Resource Model. --
class SavedResource(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='saved_resources')
    video = models.ForeignKey(Video, on_delete=models.CASCADE, null=True, blank=True)
    audio = models.ForeignKey(Audio, on_delete=models.CASCADE, null=True, blank=True)
    article = models.ForeignKey(Article, on_delete=models.CASCADE, null=True, blank=True)
    meditation = models.ForeignKey(MeditationTechnique, on_delete=models.CASCADE, null=True, blank=True)
    saved_at = models.DateTimeField(auto_now_add=True)  # Already correct


    class Meta:
        ordering = ['-saved_at']
        verbose_name = "Saved Resource"
        unique_together = [
            ['user', 'video'],
            ['user', 'audio'],
            ['user', 'article'],
            ['user', 'meditation'] 
        ]

    def __str__(self):
        return f"{self.user.username}'s saved resource"

#-- User Activity Model. --
class UserActivity(models.Model):
    """Track user engagement with resources"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='activities')
    video = models.ForeignKey(Video, on_delete=models.CASCADE, null=True, blank=True)
    audio = models.ForeignKey(Audio, on_delete=models.CASCADE, null=True, blank=True)
    article = models.ForeignKey(Article, on_delete=models.CASCADE, null=True, blank=True)
    meditation = models.ForeignKey(MeditationTechnique, on_delete=models.CASCADE, null=True, blank=True)
    completed = models.BooleanField(default=True)
    progress_percentage = models.IntegerField(default=0)
    notes = models.TextField(blank=True)
    accessed_at = models.DateTimeField(auto_now_add=True)  

    
    class Meta:
        ordering = ['-accessed_at']
        verbose_name = "User Activity"
        verbose_name_plural = "User Activities"
    
    def __str__(self):
        return f"{self.user.username} - {self.accessed_at.date()}"
    
#-- User Learning Progress Model. --
class UserLearningProgress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='learning_progress')
    
    # What resource they're tracking
    video = models.ForeignKey(Video, on_delete=models.CASCADE, null=True, blank=True)
    audio = models.ForeignKey(Audio, on_delete=models.CASCADE, null=True, blank=True)
    article = models.ForeignKey(Article, on_delete=models.CASCADE, null=True, blank=True)
    meditation_technique = models.ForeignKey(MeditationTechnique, on_delete=models.CASCADE, null=True, blank=True)
    
    # Progress tracking
    is_completed = models.BooleanField(default=False)
    completion_percentage = models.IntegerField(default=0, help_text="0-100%")
    personal_notes = models.TextField(blank=True, help_text="User's private notes about this resource")
    started_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(auto_now=True)  #  Remove default
    completed_at = models.DateTimeField(null=True, blank=True)  #  Already correct

    class Meta:
        verbose_name = "User Learning Progress"
        verbose_name_plural = "User Learning Progress"
        ordering = ['-last_accessed']
    
    def __str__(self):
        return f"{self.user.username}'s progress - {self.completion_percentage}% complete"

#-- Onboarding State Model. --
class OnboardingState(models.Model):
    GOAL_CHOICES = [
        ('reduce_stress', 'Reduce Stress'),
        ('improve_focus', 'Improve Focus'),
        ('support_team', 'Support My Team'),
        ('improve_focus', 'Improve Focus'),
        ('improve_sleep', 'Improve Sleep Quality'),
        ('manage_anxiety', 'Manage Anxiety'),
        ('manage_depression', 'Manage Depression'),
        ('self_awareness', 'Increase Self-Awareness'),
        ('mental_fitness', 'Strengthen Mental Fitness'),
        ('navigate_change', 'Navigate Life or Work Transitions'),

        ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    goal = models.CharField(default='manage_depression', max_length=50, choices=GOAL_CHOICES)
    completed = models.BooleanField(default=True)
    first_action_done = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} - Onboarding"    
    
#-- Dynamic Question Model. --
class DynamicQuestion(models.Model):
    text = models.TextField()
    category = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)


# ===== ASSESSMENT QUESTIONNAIRE MODELS =====

class AssessmentQuestion(models.Model):
    """Questions for PHQ-9 and GAD-7 assessments"""
    ASSESSMENT_TYPE_CHOICES = [
        ('PHQ-9', 'Patient Health Questionnaire (PHQ-9)'),
        ('GAD-7', 'Generalized Anxiety Disorder (GAD-7)'),
    ]
    
    assessment_type = models.CharField(max_length=10, choices=ASSESSMENT_TYPE_CHOICES)
    question_number = models.PositiveIntegerField()
    question_text = models.TextField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['assessment_type', 'question_number']
        unique_together = ['assessment_type', 'question_number']
        verbose_name = "Assessment Question"
        verbose_name_plural = "Assessment Questions"
    
    def __str__(self):
        return f"{self.assessment_type} Q{self.question_number}: {self.question_text[:50]}"


class AssessmentResponse(models.Model):
    """User responses to assessment questions"""
    SCORE_CHOICES = [
        (0, 'Not at all'),
        (1, 'Several days'),
        (2, 'More than half the days'),
        (3, 'Nearly every day'),
    ]
    
    DIFFICULTY_CHOICES = [
        ('not_difficult', 'Not difficult at all'),
        ('somewhat_difficult', 'Somewhat difficult'),
        ('very_difficult', 'Very Difficult'),
        ('extremely_difficult', 'Extremely Difficult'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='assessment_responses')
    assessment_type = models.CharField(max_length=10, choices=[('PHQ-9', 'PHQ-9'), ('GAD-7', 'GAD-7')])
    responses = models.JSONField(help_text="Array of scores for each question")
    total_score = models.PositiveIntegerField()
    severity_level = models.CharField(max_length=50)
    difficulty_level = models.CharField(max_length=30, choices=DIFFICULTY_CHOICES, null=True, blank=True)
    completed_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-completed_at']
        verbose_name = "Assessment Response"
        verbose_name_plural = "Assessment Responses"
    
    def __str__(self):
        return f"{self.user.username} - {self.assessment_type} ({self.total_score})"
    
    def calculate_severity(self):
        """Calculate severity based on total score"""
        if self.assessment_type == 'PHQ-9':
            if self.total_score <= 4:
                return "Minimal depression"
            elif self.total_score <= 9:
                return "Mild depression"
            elif self.total_score <= 14:
                return "Moderate depression"
            elif self.total_score <= 19:
                return "Moderately severe depression"
            else:
                return "Severe depression"
        
        elif self.assessment_type == 'GAD-7':
            if self.total_score <= 4:
                return "Minimal anxiety"
            elif self.total_score <= 9:
                return "Mild anxiety"
            elif self.total_score <= 14:
                return "Moderate anxiety"
            else:
                return "Severe anxiety"
        
        return "Unknown"
    
    def get_recommendations(self):
        """Get recommendations based on severity"""
        recommendations = []
        
        if self.assessment_type == 'PHQ-9':
            if self.total_score <= 4:
                recommendations = [
                    "Your responses suggest minimal depression symptoms.",
                    "Continue with healthy lifestyle habits.",
                    "Practice self-care and stress management."
                ]
            elif self.total_score <= 9:
                recommendations = [
                    "Your responses suggest mild depression symptoms.",
                    "Consider talking to a mental health professional.",
                    "Try meditation and mindfulness exercises.",
                    "Maintain regular sleep and exercise routines."
                ]
            elif self.total_score <= 14:
                recommendations = [
                    "Your responses suggest moderate depression symptoms.",
                    "We recommend consulting with a mental health professional.",
                    "Consider therapy or counseling.",
                    "Reach out to support groups or trusted friends."
                ]
            else:
                recommendations = [
                    "Your responses suggest significant depression symptoms.",
                    "Please consult with a mental health professional as soon as possible.",
                    "Consider contacting a crisis helpline if you're in immediate distress.",
                    "You don't have to face this alone - help is available."
                ]
        
        elif self.assessment_type == 'GAD-7':
            if self.total_score <= 4:
                recommendations = [
                    "Your responses suggest minimal anxiety symptoms.",
                    "Continue with healthy coping strategies.",
                    "Practice relaxation techniques regularly."
                ]
            elif self.total_score <= 9:
                recommendations = [
                    "Your responses suggest mild anxiety symptoms.",
                    "Consider learning anxiety management techniques.",
                    "Try breathing exercises and meditation.",
                    "Talk to someone you trust about your concerns."
                ]
            elif self.total_score <= 14:
                recommendations = [
                    "Your responses suggest moderate anxiety symptoms.",
                    "We recommend consulting with a mental health professional.",
                    "Consider therapy such as CBT (Cognitive Behavioral Therapy).",
                    "Practice stress reduction techniques daily."
                ]
            else:
                recommendations = [
                    "Your responses suggest significant anxiety symptoms.",
                    "Please consult with a mental health professional.",
                    "Consider professional treatment options.",
                    "Reach out for support - you don't have to manage this alone."
                ]
        
        return recommendations
    
    def save(self, *args, **kwargs):
        # Calculate total score
        if isinstance(self.responses, list):
            self.total_score = sum(self.responses)
        
        # Calculate severity
        self.severity_level = self.calculate_severity()
        
        super().save(*args, **kwargs)
