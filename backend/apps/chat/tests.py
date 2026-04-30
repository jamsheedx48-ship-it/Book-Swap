from django.test import TestCase
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from django.urls import path, include
from rest_framework_simplejwt.tokens import RefreshToken
from apps.chat.models import Conversation, Message

User = get_user_model()


class ChatTest(TestCase):
    def setUp(self):
        self.client = APIClient()

        # create users
        self.user1 = User.objects.create_user(
            name="User1",
            email="user1@test.com",
            password="123456",
            is_verified=True
        )

        self.user2 = User.objects.create_user(
            name="User2",
            email="user2@test.com",
            password="123456",
            is_verified=True
        )

        # authenticate user1
        refresh = RefreshToken.for_user(self.user1)
        self.client.cookies["access_token"] = str(refresh.access_token)

    # ---------------- START CONVERSATION ----------------
    def test_start_conversation(self):
        res = self.client.post("/api/chat/conversations/start/", {
            "user_id": self.user2.id
        })

        self.assertEqual(res.status_code, 200)
        self.assertIn("conversation_id", res.data)

    def test_start_existing_conversation(self):
        convo = Conversation.objects.create()
        convo.participants.add(self.user1, self.user2)

        res = self.client.post("/api/chat/conversations/start/", {
            "user_id": self.user2.id
        })

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["conversation_id"], convo.id)

    # ---------------- LIST CONVERSATIONS ----------------
    def test_list_conversations(self):
        convo = Conversation.objects.create()
        convo.participants.add(self.user1, self.user2)

        res = self.client.get("/api/chat/conversations/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.data), 1)

    # ---------------- MESSAGE LIST ----------------
    def test_message_list(self):
        convo = Conversation.objects.create()
        convo.participants.add(self.user1, self.user2)

        Message.objects.create(
            conversation=convo,
            sender=self.user1,
            message="Hello"
        )

        res = self.client.get(f"/api/chat/conversations/{convo.id}/messages/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.data), 1)

    # ---------------- SECURITY TEST ----------------
    def test_message_access_denied(self):
        # user1 NOT part of this conversation
        user3 = User.objects.create_user(
            name="User3",
            email="user3@test.com",
            password="123456"
        )

        convo = Conversation.objects.create()
        convo.participants.add(self.user2, user3)

        res = self.client.get(f"/api/chat/conversations/{convo.id}/messages/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.data), 0)  # should not access