import os
from django.core.files.storage import default_storage
from PIL import Image
import json
from django.forms import ValidationError
from django.http import JsonResponse
from .models import Category,Note
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime
from django.core.paginator import Paginator
from django.core.validators import MaxLengthValidator
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
import uuid
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authentication import BaseAuthentication
# from .models import UploadedFile
from urllib.parse import unquote
from django.core.files.storage import FileSystemStorage


User = get_user_model()

@csrf_exempt
def signup(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body.decode('utf-8'))
            username = body.get('username')
            email = body.get('email')
            password = body.get('password')

            if not (username and email and password):
                return JsonResponse({"error": "Missing required fields."}, status=400)

            if User.objects.filter(username=username).exists():
                return JsonResponse({"error": "Username already exists."}, status=400)

            if User.objects.filter(email=email).exists():
                return JsonResponse({"error": "Email already exists."}, status=400)

            my_user = User.objects.create_user(username=username, email=email, password=password)
            my_user.is_staff = True 
            my_user.is_superuser = True  
            my_user.save()  

            user_uuid = uuid.uuid4()

            return JsonResponse({
                "user": {
                    "username": username,
                    "email": email,
                    "uuid": str(user_uuid), 
                },
            }, status=201)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format."}, status=400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def login(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body.decode('utf-8'))
            email = body.get('email')
            password = body.get('password')

            if not (email and password):
                return JsonResponse({"error": "Missing required fields."}, status=400)

            user = User.objects.filter(email=email).first()
            if not user:
                return JsonResponse({"error": "User not found."}, status=400)

            if not user.check_password(password):
                return JsonResponse({"error": "Incorrect password."}, status=400)

            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token

            return JsonResponse({
                "user": {
                    "username": user.username,
                    "email": user.email,
                },
                "refresh": str(refresh),
                "access": str(access_token)
            }, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format."}, status=400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
@csrf_exempt
@permission_classes(IsAuthenticated)
def createnote(request):
    if request.method == 'POST':
        try:
            uploaded_image = None
            image_url = None

            if 'multipart/form-data' in request.content_type:
                if "image" in request.FILES:
                    uploaded_image = request.FILES["image"]
                    try:
                        ext = uploaded_image.name.split(".")[-1].lower()
                        allowed_extensions = ["jpg", "jpeg", "png", "gif", "bmp"]
                        
                        if ext not in allowed_extensions:
                            raise ValidationError("Invalid image format. Allowed formats: jpg, jpeg, png, gif, bmp.")
                        if not uploaded_image.content_type.startswith('image'):
                            raise ValidationError("Uploaded file is not an image.")
                        
                        max_size = 5 * 1024 * 1024  # 5MB
                        if uploaded_image.size > max_size:
                            raise ValidationError("Image size exceeds the maximum allowed size of 5MB.")
                        
                        image = Image.open(uploaded_image)
                        image.verify()
                    
                    except ValidationError as e:
                        return JsonResponse({"error": str(e)}, status=400)

                    title = request.POST.get('title')
                    content = request.POST.get('content')
                    category_name = request.POST.get('category')

                    if category_name:
                        category, created = Category.objects.get_or_create(categoryName=category_name)
                    else:
                        category = None

                    new_note = Note.objects.create(
                        title=title,
                        content=content,
                        category=category,
                        file=uploaded_image
                    )

                    image_url = new_note.get_photo_url()

                    return JsonResponse({
                        "message": "Note created and image uploaded successfully!",
                        "file_name": uploaded_image.name,
                        "image_url": image_url,
                        "title": new_note.title,
                        "content": new_note.content,
                        "category": new_note.category.categoryName if new_note.category else None
                    }, status=201)
                else:
                    return JsonResponse({"error": "No image uploaded"}, status=400)

            title = request.POST.get('title')
            content = request.POST.get('content')
            category_name = request.POST.get('category')

            if category_name:
                category, created = Category.objects.get_or_create(categoryName=category_name)
            else:
                category = None

            new_note = Note.objects.create(
                title=title,
                content=content,
                category=category,
            )

            return JsonResponse({
                "message": "Note created successfully!",
                "file_name": None,
                "image_url": None,
                "title": new_note.title,
                "content": new_note.content,
                "category": new_note.category.categoryName if new_note.category else None
            }, status=201)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid HTTP method."}, status=405)

# List notes
def listNotes(request, note_id=None):
    if request.method == 'GET':
        try:
            note_filter = request.GET.get('note')
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('limit', 10))

            if note_filter:
                category = Category.objects.filter(categoryName=note_filter).first()
                if category:
                    notes = Note.objects.filter(category=category)
                else:
                    notes = []
            else:
                if note_id:
                    notes = Note.objects.filter(note_id=note_id)
                else:
                    notes = Note.objects.all()

            paginator = Paginator(notes, limit)
            page_obj = paginator.get_page(page)
            
            note_data = [
                {
                    'note_id': note.note_id,
                    'title': note.title,
                    'category': note.category.categoryName if note.category else None,
                    'content': note.content,
                    'created_at': note.created_at,
                    'updated_at': note.updated_at
                }
                for note in page_obj
            ]
            

            return JsonResponse({
                "notes": note_data,
                "page": page_obj.number,
                "total_pages": paginator.num_pages,
                "total_items": paginator.count,
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Method Not Allowed"}, status=405)


def specificNote(request, note_id=None):
    if request.method == 'GET':
        try:
            note = Note.objects.get(note_id=note_id)
            print(f"Get Specific Note ID: {note_id}")
            
            image_url = note.get_photo_url() 

            return JsonResponse({
                'note_id': note.note_id,
                'title': note.title,
                'category': note.category.categoryName if note.category else None,
                'content': note.content,
                'created_at': note.created_at,
                'updated_at': note.updated_at,
                'image_url': image_url 
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Method Not Allowed"}, status=405)




# Delete Todo Function Code
@csrf_exempt
def deleteNote(request, note_id):
    if request.method == 'DELETE':
        try:       
            auth_header = request.headers.get('Authorization', None)
            if not auth_header:
                return JsonResponse({"error": "Authorization header missing."}, status=401)
            
            token = auth_header.split(" ")[1] if " " in auth_header else None
            if not token:
                return JsonResponse({"error": "Bearer token missing."}, status=401)
            
            try:
                JWTAuthentication().authenticate(request)  
            except AuthenticationFailed:
                return JsonResponse({"error": "Invalid or expired token."}, status=401)
            
            print(f"Attempting to delete note with note_id: {note_id}")
            
            note = Note.objects.filter(note_id=note_id)
            
            if not note:
                return JsonResponse({"error": "Note Not Found"}, status=404)

            note.delete()

            return JsonResponse({"success": f"Note with Note {note_id} deleted successfully."}, status=200)

        except Exception as e:
            print(f"Error occurred while deleting note: {e}") 
            return JsonResponse({"error": str(e)}, status=500)




@csrf_exempt
def updateNote(request, note_id):
    if request.method != 'PUT':
        return JsonResponse({"error": "Invalid HTTP method."}, status=405)

    try:
        # Authorization Check
        auth_header = request.headers.get('Authorization', None)
        if not auth_header or " " not in auth_header:
            return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

        token = auth_header.split(" ")[1]
        try:
            JWTAuthentication().authenticate(request)
        except AuthenticationFailed:
            return JsonResponse({"error": "Invalid or expired token."}, status=401)

        note = Note.objects.get(note_id=note_id)
    except Note.DoesNotExist:
        return JsonResponse({'error': 'Note Not Found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    try:
        title = request.POST.get('title')
        category = request.POST.get('category')
        content = request.POST.get('content')
        image_file = request.FILES.get('image')  # Image handling

        print("Title:", title)
        print("Category:", category)
        print("Content:", content)
        print("Image File:", image_file)

        if not title:
            return JsonResponse({'error': 'Title is required'}, status=400)

        # Update the note fields
        note.title = title
        note.category = category
        note.content = content

        if image_file:
            fs = FileSystemStorage()
            filename = fs.save(image_file.name, image_file)  # Save image
            note.image_url = fs.url(filename)  # Store image URL

        note.save()

        # Prepare response
        response_data = {
            'note_id': note_id,
            'title': title,
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'category': category,
            'content': content,
            'image_url': note.image_url
        }
        return JsonResponse(response_data, status=200)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)





@csrf_exempt
def createCategory(request):
    if request.method == 'POST':
        try:
            
            auth_header = request.headers.get('Authorization', None)
            if not auth_header:
                return JsonResponse({"error": "Authorization header missing."}, status=401)
            
            token = auth_header.split(" ")[1] if " " in auth_header else None
            if not token:
                return JsonResponse({"error": "Bearer token missing."}, status=401)
            
            try:
                JWTAuthentication().authenticate(request)  
            except AuthenticationFailed:
                return JsonResponse({"error": "Invalid or expired token."}, status=401)
            
            body = json.loads(request.body.decode('utf-8'))
            categoryName = body.get('categoryName')

            if not categoryName:
                return JsonResponse({'message': "Missing required field"}, status=400)
            
            max_length = 10
            if len(categoryName) > max_length:
                return JsonResponse({"error": f"categoryName must not exceed {max_length} characters."}, status=400)

            try:
                MaxLengthValidator(max_length)(categoryName)
            except ValidationError as e:
                return JsonResponse({"error": e.message}, status=400)

            new_category = Category.objects.create(categoryName=categoryName)
            new_category.save()

            my_user = request.user  

            if my_user.is_authenticated:  
                refresh = RefreshToken.for_user(my_user)
                access_token = refresh.access_token
            else:
                return JsonResponse({"error": "User is not authenticated"}, status=401)

            return JsonResponse({
                "category": {
                    'id': new_category.id,
                    'categoryName': new_category.categoryName
                },
                "tokens": {
                    'access_token': str(access_token),
                    'refresh_token': str(refresh)
                }
            }, status=201)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Method Not Allowed"}, status=405)



def listCategories(request):
    if request.method == 'GET':
        try:
            category_name = request.GET.get('category')
            page = int(request.GET.get('page', 1)) 
            limit = int(request.GET.get('limit', 10))  
            if category_name:
                categories = Category.objects.filter(categoryName__icontains=category_name)
            else:
                categories = Category.objects.all()

            paginator = Paginator(categories, limit)
            page_obj = paginator.get_page(page)
            
            category_data = [
                {
                    "id": cat.id,
                    "title": cat.categoryName
                }
                for cat in page_obj
            ]

            return JsonResponse({
                "categories": category_data,
                "page": page_obj.number,
                "total_pages": paginator.num_pages,
                "total_items": paginator.count,
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Method Not Allowed"}, status=405)


def image_update(request):
    pass