from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, filters, permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework.pagination import PageNumberPagination
from django.db.models import Q
from .models import Book, Category
from .serializers import BookSerializer, CategorySerializer
from .tasks import process_book_image,enrich_book_description_task,ingest_book_to_qdrant
from django.db import transaction

# Create your views here.

class BookPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 50

# for listing and geting books
class BookListCreateAPIView(APIView):
    def get_permissions(self):
        if self.request.method=="POST":
            return [permissions.IsAuthenticated()]
        return [permissions.AllowAny()]
    
    def get(self,request):
        queryset= Book.objects.select_related('user', 'category').filter(deleted_at__isnull=True).order_by('-created_at')

        # Filter by category
        category= request.query_params.get('category')
        if category:
            queryset=queryset.filter(category__id=category)

        # Filter by condition
        condition=request.query_params.get('condition')
        if condition:
            queryset=queryset.filter(condition=condition)

        # Search by title, author, category name
        search=request.query_params.get('search')    
        if search:
            queryset=queryset.filter(
                Q(title__icontains=search)|
                Q(author__icontains=search)|
                Q(category__name__icontains=search)
            )
        
        #pagination
        paginator=BookPagination()
        page=paginator.paginate_queryset(queryset,request)
        serializer=BookSerializer(page,many=True)
        return paginator.get_paginated_response(serializer.data)
    
    #post books
    def post(self,request):
        serializer=BookSerializer(data=request.data)
        if serializer.is_valid():
            with transaction.atomic():
                book=serializer.save(user=request.user)

                def trigger_tasks():
                    # image processing task
                    if book.image:
                        process_book_image.delay(book.id,book.image.name)
            
                    # long description enrichment task
                    enrich_book_description_task.delay(book.id)

                #only after full comit run celery tasks    
                transaction.on_commit(trigger_tasks)
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    
#Book detail Edit your listing,Delete your listing
class BookDetailAPIView(APIView):
    def get_permissions(self):
        if self.request.method == 'GET':
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated()]
    
    def get_object(self, pk, request):
        try:
            book=Book.objects.select_related('user','category').get(pk=pk,deleted_at__isnull=True)
        except Book.DoesNotExist:
            return None,Response(
                {"error":"Book not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # For write methods, check ownership
        if request.method != 'GET' and book.user != request.user:
            return None, Response(
                {'error': 'You can only modify your own listings.'},
                status=status.HTTP_403_FORBIDDEN
            )
        return book,None

    # FOR GETING BOOK DETAIL
    def get(self,request,pk):
        book,error=self.get_object(pk,request)
        if error:
            return error
        serializer=BookSerializer(book)
        return Response(serializer.data,status=status.HTTP_200_OK)
    
    #for editing a book
    def put(self,request, pk):
        book,error=self.get_object(pk,request)
        if error:
            return error
        serializer=BookSerializer(book,data=request.data,partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # soft DELETE - move to trash
    def delete(self, request, pk):
        book, error = self.get_object(pk, request)
        if error:
            return error
        book.soft_delete()
        return Response(
            {'message': 'Book moved to trash.'},
            status=status.HTTP_200_OK
        )

# List user's trashed books
class BookTrashListAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        queryset = Book.objects.filter(
            user=request.user,
            deleted_at__isnull=False
        ).order_by('-deleted_at')
        serializer = BookSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# Restore a trashed book
class BookRestoreAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            book = Book.objects.get(pk=pk, user=request.user, deleted_at__isnull=False)
        except Book.DoesNotExist:
            return Response({'error': 'Book not found in trash.'}, status=status.HTTP_404_NOT_FOUND)
        book.restore()
        return Response({'message': 'Book restored successfully.'}, status=status.HTTP_200_OK)

# Permanently delete a trashed book
class BookPermanentDeleteAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, pk):
        try:
            book = Book.objects.get(pk=pk, user=request.user, deleted_at__isnull=False)
        except Book.DoesNotExist:
            return Response({'error': 'Book not found in trash.'}, status=status.HTTP_404_NOT_FOUND)
        
        if book.image:
            book.image.delete(save=False)
        book.delete()
        return Response({'message': 'Book permanently deleted.'}, status=status.HTTP_204_NO_CONTENT)
    

# List all categories (for dropdownin frontend)
class CategoryListAPIView(APIView):
    def get_permissions(self):
        if self.request.method == 'POST':
            return [permissions.IsAdminUser()]
        return [permissions.AllowAny()]

    def get(self, request):
        categories = Category.objects.all()
        serializer = CategorySerializer(categories, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class MyBooksView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        books = Book.objects.filter(user=request.user)
        serializer = BookSerializer(books, many=True)
        return Response(serializer.data)