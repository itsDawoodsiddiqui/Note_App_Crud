from django.db import models
import uuid
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from urllib.parse import urljoin

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
    file = models.FileField(upload_to='uploads/', null=True, blank=True)  # Ensure file field is correct
    
    def __str__(self):
        return self.title
    
    def get_photo_url(self):
        return self.file.url if self.file else None


# class UploadedFile(models.Model):
#     file = models.FileField(upload_to='uploads/')  # File store location
#     uploaded_at = models.DateTimeField(auto_now_add=True)

#     def get_photo_url(self, request=None):
#         # Construct the absolute URL manually
#         if request:
#             base_url = request.build_absolute_uri('/')  
#             return urljoin(base_url, self.file.url)  
#         return self.file.url  

#     def __str__(self):
#         return self.file.name

class Signup(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    user_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username
