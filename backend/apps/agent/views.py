from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings

# Book model -> stores all listed books
from apps.books.models import Book

# Exchange model -> stores swap requests between users
from apps.exchanges.models import Exchange

# Converts Book queryset/object into JSON response
from apps.books.serializers import BookSerializer

# Converts Exchange queryset/object into JSON response
from apps.exchanges.serializers import ExchangeSerializer


# Secret key used to ensure only internal AI agent can access these endpoints
INTERNAL_SECRET = settings.AGENT_INTERNAL_SECRET


def check_secret(request):
    """
    Checks whether request contains valid internal secret.
    
    AI agent must send:
    X-Internal-Secret: your_secret_key
    
    Prevents normal users from directly accessing these APIs.
    """
    return request.headers.get("X-Internal-Secret") == INTERNAL_SECRET


class UserBooksView(APIView):
    """
    Returns all books owned by a specific user.
    
    Example:
    Agent asks -> What books does user 5 own?
    """

    def get(self, request):
        # Block request if secret is invalid
        if not check_secret(request):
            return Response(
                {"detail": "Forbidden"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get user id from query params
        # Example: /api/user-books/?user_id=5
        user_id = request.query_params.get("user_id")

        # Fetch active books (not deleted)
        books = Book.objects.filter(
            user_id=user_id,
            deleted_at__isnull=True
        )

        # Return books as JSON
        return Response(
            BookSerializer(books, many=True).data
        )

class WhoWantsMyBooksView(APIView):
    def get(self, request):
        if not check_secret(request):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
        user_id = request.query_params.get("user_id")
        exchanges = Exchange.objects.filter(
            requested_book__user_id=user_id,
            status=Exchange.Status.PENDING
        ).select_related('requester', 'offered_book', 'requested_book')
        
        data = []
        for ex in exchanges:
            data.append({
                "exchange_id": ex.id,
                "requester_id": ex.requester.id,
                "requester_name": ex.requester.name,
                "offered_book_id": ex.offered_book.id,
                "offered_book_title": ex.offered_book.title,
                "requested_book_id": ex.requested_book.id,
                "requested_book_title": ex.requested_book.title,
            })
        
        return Response(data)


class BookOwnersView(APIView):
    """
    Returns owner details for a specific book.
    
    Example:
    Agent wants to know who owns 'Rich Dad Poor Dad'
    """

    def get(self, request):
        # Validate internal secret
        if not check_secret(request):
            return Response(
                {"detail": "Forbidden"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get book id from query params
        # Example: /api/book-owners/?book_id=10
        book_id = request.query_params.get("book_id")

        # Fetch book and related owner
        books = Book.objects.filter(
            id=book_id,
            deleted_at__isnull=True
        ).select_related('user')

        # Return book + owner info
        return Response(
            BookSerializer(books, many=True).data
        )


class CreateExchangeView(APIView):
    """
    Creates a new exchange request automatically.
    
    Used when AI agent finds a good swap match.
    """

    def post(self, request):
        # Validate internal secret
        if not check_secret(request):
            return Response(
                {"detail": "Forbidden"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get incoming request data
        data = request.data
        print("AGENT EXCHANGE DATA:", data)  # ← add this
        # Create exchange record
        exchange = Exchange.objects.create(
            requester_id=data["requester_id"],
            receiver_id=data["receiver_id"],
            offered_book_id=data["offered_book_id"],
            requested_book_id=data["requested_book_id"],

            # Default message if none provided
            message=data.get(
                "message",
                "Matched by BookSwap AI Agent"
            ),
        )

        # Return newly created exchange id
        return Response(
            {"exchange_id": exchange.id},
            status=status.HTTP_201_CREATED
        )