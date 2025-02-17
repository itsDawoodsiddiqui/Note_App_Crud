from .models import Category, Note
from django.contrib import admin
# from .models import UploadedFile
from .models import Signup
@admin.register(Category)  
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'categoryName') 
    
@admin.register(Note)
class NoteAdmin(admin.ModelAdmin):
    list_display = ('note_id', 'title', 'content', 'category', 'created_at', 'updated_at', 'get_file_url')
    
    def get_file_url(self, obj):
        return obj.get_photo_url()  
    get_file_url.short_description = 'Image URL' 


@admin.register(Signup)
class SignupAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'user_id', 'created_at')
    search_fields = ('username', 'email')

# admin.site.register(UploadedFile)