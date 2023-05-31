
from typing import Iterable, Optional
from django.db import models
from django.core.validators import MinValueValidator
from django.apps import apps
from django.contrib import auth
from django.contrib.auth.hashers import make_password

# from django.contrib.auth.models import User

STATUS_CHOICES = (
    ("PENDING", "PENDING"),
    ("IN_PROGRESS", "IN_PROGRESS"),
    ("COMPLETED", "COMPLETED"),
    ("CANCELLED", "CANCELLED"),
)


# from django.contrib.auth.models import User
from django.db import models

class UserManager():
    pass

from django.contrib.auth.models import AbstractUser
class User(AbstractUser):
    send_report_at = models.TimeField(null=True)
    last_sent_on = models.DateField(null=True)

    
class Task(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    priority = models.PositiveIntegerField(validators=[MinValueValidator(1)], blank=False, null=True)
    created_date = models.DateTimeField(auto_now=True)
    deleted = models.BooleanField(default=False)
    status = models.CharField(max_length=100, choices=STATUS_CHOICES, default=STATUS_CHOICES[0][0])
    user = models.ForeignKey(User , related_name= "tasks", on_delete=models.CASCADE , null=True,blank=True)

    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
       
        if self.pk:
            History.objects.create(old_status = Task.objects.get(id = self.pk).status, new_status = self.status, task_id = self.pk)
        super(Task, self).save(*args, **kwargs)
    
    
class History(models.Model):
    old_status = models.CharField(max_length=100, choices=STATUS_CHOICES, null=True)
    new_status = models.CharField(max_length=100, choices=STATUS_CHOICES, null=True)
    modified_date = models.DateTimeField(auto_now=True)
    task = models.ForeignKey(Task , on_delete=models.CASCADE)
