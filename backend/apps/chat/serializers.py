from rest_framework import serializers
from .models import Conversation, Message

class MessageSerializer(serializers.ModelSerializer):
    sender_name = serializers.CharField(source="sender.name", read_only=True)

    class Meta:
        model = Message
        fields = ["id", "sender", "sender_name", "message", "timestamp", "is_read"]


class ConversationSerializer(serializers.ModelSerializer):
    last_message = serializers.SerializerMethodField()
    other_user = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()


    class Meta:
        model = Conversation
        fields = ["id", "created_at", "other_user", "last_message","unread_count"]

    def get_last_message(self, obj):
        last = obj.messages.last()
        if last:
            return {"message": last.message, "timestamp": str(last.timestamp)}
        return None

    def get_other_user(self, obj):
        request = self.context["request"]
        other = obj.participants.exclude(id=request.user.id).first()
        if other:
            return {"id": other.id, "name": other.name}
        return None
    
    def get_unread_count(self, obj):
        request = self.context["request"]
        return obj.messages.filter(
            is_read=False
        ).exclude(sender=request.user).count()