
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

    def __str__(self):
        return f"{self.username} ({self.role})"
