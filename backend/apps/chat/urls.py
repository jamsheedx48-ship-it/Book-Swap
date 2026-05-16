from django.urls import path
from . import views

urlpatterns = [
    path("conversations/", views.ConversationListView.as_view()),
    path("conversations/start/", views.StartConversationView.as_view()),
    path("conversations/<int:conversation_id>/messages/", views.MessageListView.as_view()),
    # path('unread-count/', views.UnreadMessageCountView.as_view()),
]