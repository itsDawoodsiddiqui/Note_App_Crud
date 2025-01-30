from django.urls import path
from . import views
# from .views import RegisterView  # Import your RegisterView if needed

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
]
