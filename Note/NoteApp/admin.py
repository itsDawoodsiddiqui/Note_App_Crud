from .models import Category, Note
from django.contrib import admin
# from .models import UploadedFile

@admin.register(Category)  
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'categoryName') 
    
@admin.register(Note)
class NoteAdmin(admin.ModelAdmin):
    list_display = ('note_id', 'title', 'content', 'category', 'created_at', 'updated_at', 'get_file_url')
    
    def get_file_url(self, obj):
        return obj.get_photo_url()  # No need for request here
    get_file_url.short_description = 'Image URL' 



# admin.site.register(UploadedFile)