import httpx
import os
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from ..profiles.models import Genre
from ..exchanges.models import Exchange
from ..books.models import Book

AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://ai_service:8001/api/ai/recommend")


class BookRecommendationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # 1. Get user interests
        try:
            raw_interests = list(user.profile.interests.values_list("name", flat=True))
            interests = [Genre(name=g).get_name_display() for g in raw_interests]
        except Exception:
            interests = []

        # 2. Get swapped books
        sent = Exchange.objects.filter(
            requester=user, status=Exchange.Status.COMPLETED
        ).select_related("offered_book")[:10]

        received = Exchange.objects.filter(
            receiver=user, status=Exchange.Status.COMPLETED
        ).select_related("requested_book")[:10]

        swapped_books = (
            [e.offered_book.title for e in sent] +
            [e.requested_book.title for e in received]
        )

        # 3. Find matching books from your platform by genre
        platform_books = []
        if raw_interests:
            local_books = Book.objects.filter(
                category__name__in=raw_interests
            ).exclude(
                user=user
            ).select_related("category").order_by("?")[:6]

            platform_books = [
                {
                    "id": b.id,
                    "title": b.title,
                    "author": b.author,
                    "genre": b.category.get_name_display() if b.category else "",
                    "cover": b.image_thumbnail or b.image or None,
                }
                for b in local_books
            ]

        # 4. Call FastAPI for global suggestions
        try:
            with httpx.Client(timeout=15) as client:
                res = client.post(AI_SERVICE_URL, json={
                    "interests": interests,
                    "swapped_books": swapped_books,
                    "user_id": str(user.id),
                })
                res.raise_for_status()
                global_books = res.json().get("recommendations", [])
        except httpx.HTTPError:
            global_books = []

        return Response({
            "platform_books": platform_books,
            "global_books": global_books,
        })