from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, filters, permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework.pagination import PageNumberPagination
from django.db.models import Q
from .models import Book, Category
from .serializers import BookSerializer, CategorySerializer
# Create your views here.

class BookPagination(PageNumberPagination):
    page_size = 2
    page_size_query_param = 'page_size'
    max_page_size = 50

# for listing and geting books
class BookListCreateAPIView(APIView):
    def get_permissions(self):
        if self.request.method=="POST":
            return [permissions.IsAuthenticated()]
        return [permissions.AllowAny()]
    
    def get(self,request):
        queryset= Book.objects.select_related('user', 'category').all().order_by('-created_at')

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
            serializer.save(user=request.user)
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    
#Book detail,Edit your listing,Delete your listing
class BookDetailAPIView(APIView):
    def get_permissions(self):
        if self.request.method == 'GET':
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated()]
    
    def get_object(self, pk, request):
        try:
            book=Book.objects.select_related('user','category').get(pk=pk)
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

    # DELETE book
    def delete(self, request, pk):
        book, error = self.get_object(pk, request)
        if error:
            return error
        
        if book.image:
            book.image.delete(save=False)
        book.delete()
        return Response(
            {'message': 'Book deleted successfully.'},
            status=status.HTTP_204_NO_CONTENT
        )

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