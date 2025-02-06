from django.urls import path
from . import views
# from .views import RegisterView  # Import your RegisterView if needed
from django.conf import settings
from django.conf.urls.static import static
# from .views import upload_image, get_uploaded_files, delete_image_by_id


urlpatterns = [
    # Category and Note Routes
    path('new/category/', views.createCategory, name='createCategory'),
    path('categories/', views.listCategories, name="listCategories"),
    
    path('new/note/', views.createnote, name="note"),
    path('deletenote/<str:note_id>/', views.deleteNote, name='deleteNote'),
    path('updateNote/<str:note_id>/', views.updateNote, name='updateNote'),

    path('notes/', views.listNotes, name="listNotes"),
    path('note/<str:note_id>/', views.specificNote, name="specificNote"),
  # User Authentication Routes
    path('signup/', views.signup, name='signup'),  # User registration
    path('login/', views.login, name='login'),  # User login
        
    # path('upload/', views.upload_image, name='upload_file'),
    # path('files/', views.get_uploaded_files, name='get_uploaded_files'),
    # path('delete/<int:id>/', views.delete_image_by_id, name='delete_file_by_id'),


  
        
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
