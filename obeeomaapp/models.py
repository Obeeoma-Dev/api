

# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.db import models

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

    def __str__(self):
        return f"{self.username} ({self.role})"

from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator


class Organization(models.Model):
    name = models.CharField(max_length=255, unique=True)
    joined_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self) :
        return str(self.name)

    class Meta:
        """ Meta options for Organization model """
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


class AIManagement(models.Model):
    organization = models.ForeignKey(Organization,
                                     on_delete=models.CASCADE,
                                     related_name="managements")
    title = models.CharField(max_length=255)
    description = models.TextField()
    effectiveness = models.DecimalField(
        max_digits=5, decimal_places=2,
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
    spike_percentage = models.DecimalField(
        max_digits=5, decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    recorded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Hotline Activity - {self.organization.name} ({self.recorded_at})"

    class Meta:
        ordering = ['-recorded_at']
        verbose_name_plural = "Hotline Activities"


class ClientEngagement(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="engagements")
    engagement_rate = models.DecimalField(
        max_digits=5, decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
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
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="subscriptions"
    )
    plan = models.CharField(
        max_length=50,
        choices=PLAN_CHOICES,
        default="Free"
    )
    revenue = models.DecimalField(  # ← corrected field name
        max_digits=10,
        decimal_places=2,
        default=0.00
    )
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

