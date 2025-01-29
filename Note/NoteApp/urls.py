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
    
    # If you're using the RegisterView CBV, you can keep this or remove the 'signup' path
    # path('register/', RegisterView.as_view(), name='register'),  # Class-based registration view
    
    # Additional paths (Uncomment if needed)
    # path('hello/', views.hello_world, name='hello_world'),
    # path('customer/', views.customer_list, name="cusotmer_list"),
    # path('customers/', views.customer_list, name='customer_list'),
    # path('add/', views.add_customer, name='add_customer'),
]
