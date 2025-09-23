
# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    onboarding_completed = models.BooleanField(default=False)

    def __str__(self):
        return self.username
