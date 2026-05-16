from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Conversation, Message
from .serializers import ConversationSerializer, MessageSerializer
from django.contrib.auth import get_user_model
# Create your views here.
User=get_user_model()

#all conversation of loged in user
class ConversationListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        conversations = Conversation.objects.filter(participants=request.user)
        serializer = ConversationSerializer(conversations, many=True, context={"request": request})
        return Response(serializer.data)
    
#Finds existing conversation between two users or creates a new one”
class StartConversationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        other_user_id = request.data.get("user_id")
        other_user = User.objects.get(id=other_user_id)

        conversation = Conversation.objects.filter(
            participants=request.user
        ).filter(
            participants=other_user
        ).first()

        if not conversation:
            conversation = Conversation.objects.create()
            conversation.participants.add(request.user, other_user)

        return Response({"conversation_id": conversation.id})

class MessageListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, conversation_id):
        messages = Message.objects.filter(conversation_id=conversation_id,conversation__participants=request.user)
        messages.exclude(sender=request.user).update(is_read=True)
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)
    

# class UnreadMessageCountView(APIView):
#     permission_classes = [IsAuthenticated]

#     def get(self, request):
#         count = Message.objects.filter(
#             conversation__participants=request.user,
#             is_read=False
#         ).exclude(sender=request.user).count()
#         return Response({'unread_count': count})