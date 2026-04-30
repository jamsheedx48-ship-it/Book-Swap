from django.urls import path
from .views import ConversationListView, StartConversationView, MessageListView

urlpatterns = [
    path("conversations/", ConversationListView.as_view()),
    path("conversations/start/", StartConversationView.as_view()),
    path("conversations/<int:conversation_id>/messages/", MessageListView.as_view()),
]