from .models import Category, Note
from django.contrib import admin

@admin.register(Category)  
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'categoryName') 
    
@admin.register(Note)
class NoteAdmin(admin.ModelAdmin):
    list_display = ('note_id', 'title', 'content', 'category', 'created_at', 'updated_at') 


