from django.urls import path
from . import views

urlpatterns = [
    path("", views.ExchangeListView.as_view(), name="exchange-list"),
    path("request/", views.ExchangeRequestView.as_view(), name="exchange-request"),
    path("<int:pk>/<str:action>/", views.ExchangeActionView.as_view(), name="exchange-action"),
    path("check-pending/<int:book_id>/", views.CheckPendingExchangeView.as_view(), name="check-pending"),
]