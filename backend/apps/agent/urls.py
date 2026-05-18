from django.urls import path
from .views import UserBooksView, WhoWantsMyBooksView, BookOwnersView, CreateExchangeView

urlpatterns = [
    path("books/", UserBooksView.as_view()),
    path("wanted/", WhoWantsMyBooksView.as_view()),
    path("owners/", BookOwnersView.as_view()),
    path("exchange/", CreateExchangeView.as_view()),
]