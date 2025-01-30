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
            refresh = RefreshToken.for_user(my_user)
            access_token = refresh.access_token

            return JsonResponse({
                "user": {
                    "username": username,
                    "email": email,
                    "uuid": str(user_uuid), 
                },
                "refresh": str(refresh),
                "access": str(access_token)
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
@permission_classes([IsAuthenticated])
def createnote(request):
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
            title = body.get('title')
            content = body.get('content')
            category_name = body.get('category')
            
            if not title:
                return JsonResponse({"error": "Title is required."}, status=400)

            if not content:
                return JsonResponse({"error": "Content is required."}, status=400)

            existing_note = Note.objects.filter(title=title, content=content).first()
            if existing_note:
                return JsonResponse({"error": "Note with this title already exist."}, status=400)
            
            max_length = 10
            if len(title) > max_length:
                return JsonResponse({"error": f"Title must not exceed {max_length} characters."}, status=400)

            try:
                MaxLengthValidator(max_length)(title)
            except ValidationError as e:
                return JsonResponse({"error": e.message}, status=400)
            
            
            max_length = 50
            if len(content) > max_length:
                return JsonResponse({"error": f"Content must not exceed {max_length} characters."}, status=400)
            try:
                MaxLengthValidator(max_length)(content)
            except ValidationError as e:
                return JsonResponse({"error": e.message}, status=400)
            

            if category_name:
                category, created = Category.objects.get_or_create(categoryName=category_name)
            else:
                category = None

            new_note = Note.objects.create(title=title, content=content, category=category)

            return JsonResponse({
                "note": {
                    "title": new_note.title,
                    "content": new_note.content,
                    "category": new_note.category.categoryName if new_note.category else None
                },
            }, status=201)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data."}, status=400)

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


# Specific note
def specificNote(request, note_id=None):
    if request.method == 'GET':
        try:
           note = Note.objects.get(note_id=note_id)
           print(f"Get Specific Note ID: {note_id}")
           return JsonResponse({
                'note_id': note.note_id,
                'title': note.title,
                'category': note.category.categoryName if note.category else None,
                'content': note.content,
                'created_at': note.created_at,
                'updated_at': note.updated_at
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
    if request.method == 'PUT':
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
            note = Note.objects.get(note_id=note_id)
            
        except Note.DoesNotExist:
            return JsonResponse({'error': 'Note Not Found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
        
        try:
            data = json.loads(request.body)
            title = data.get('title')
            category = data.get('category')
            content = data.get('content')

            if not title:
                return JsonResponse({'error': 'Title is required'}, status=400)

            note.title = title
            note.content = content
            note.save()

            response_data = {
                'note_id': note_id,
                'title': title,
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'category': category,
                'content': content
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
