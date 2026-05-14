from django.urls import path
from . import views

urlpatterns = [
    path("", views.BookRecommendationsView.as_view(), name="book-recommendations"),
]