from django.urls import path
from . import views
urlpatterns = [
    path('', views.BookListCreateAPIView.as_view(), name='book-list-create'),
    path('<int:pk>/', views.BookDetailAPIView.as_view(), name='book-detail'),
    path('categories/', views.CategoryListAPIView.as_view(), name='category-list'),
    path('trash/', views.BookTrashListAPIView.as_view(), name='book-trash-list'),
    path('trash/<int:pk>/restore/', views.BookRestoreAPIView.as_view(), name='book-restore'),
    path('trash/<int:pk>/delete/', views.BookPermanentDeleteAPIView.as_view(), name='book-permanent-delete'),


]