from django.urls import path
from .views import BookListCreateAPIView, BookDetailAPIView, CategoryListAPIView

urlpatterns = [
    path('', BookListCreateAPIView.as_view(), name='book-list-create'),
    path('<int:pk>/', BookDetailAPIView.as_view(), name='book-detail'),
    path('categories/', CategoryListAPIView.as_view(), name='category-list'),
]