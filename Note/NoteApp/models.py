from django.db import models
import uuid
from django.contrib.auth.models import AbstractUser


class Category(models.Model):
    categoryName = models.CharField(max_length=50)
    id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, primary_key=True)

    def __str__(self):
        return self.categoryName


class Note(models.Model):
    note_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    title = models.CharField(max_length=50)
    content = models.CharField(max_length=80)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
    
