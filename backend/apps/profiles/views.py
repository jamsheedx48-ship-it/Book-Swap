from django.shortcuts import render
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import Rating,UserProfile,Genre
from .serializers import UserProfilePublicSerializer,UserProfileEditSerializer,RatingSerializer,GenreSerializer


# Create your views here.

User=get_user_model()

class PublicProfileView(APIView):        
    permission_classes = [permissions.AllowAny]

    def get(self, request, user_id):
        try:
            profile = UserProfile.objects.select_related('user').get(user__id=user_id)
        except UserProfile.DoesNotExist:
            return Response({'error': 'Profile not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserProfilePublicSerializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)


class MyProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_profile(self, user):
        profile, _ = UserProfile.objects.get_or_create(user=user)
        return profile
    
    def get(self, request):
        profile = self.get_profile(request.user)
        if not profile:
            return Response({'error':"This user has no profile"})
        serializer = UserProfilePublicSerializer(profile, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        profile = request.user.profile
        serializer = UserProfileEditSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            profile.refresh_from_db()
            return Response(UserProfilePublicSerializer(profile, context={'request': request}).data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        profile = request.user.profile
        serializer = UserProfileEditSerializer(profile, data=request.data)
        if serializer.is_valid():
            serializer.save()
            profile.refresh_from_db()
            return Response(UserProfilePublicSerializer(profile, context={'request': request}).data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SubmitRatingView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, user_id):
        # can't rate yourself
        if request.user.id == user_id:
            return Response({'error': 'You cannot rate yourself.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            reviewed_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        # check if already rated
        if Rating.objects.filter(reviewer=request.user, reviewed_user=reviewed_user).exists():
            return Response({'error': 'You have already rated this user.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = RatingSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(reviewer=request.user, reviewed_user=reviewed_user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ListRatingsView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, user_id):
        try:
            reviewed_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        ratings = Rating.objects.filter(reviewed_user=reviewed_user)
        serializer = RatingSerializer(ratings, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class DeleteRatingView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, user_id):
        try:
            rating = Rating.objects.get(reviewer=request.user, reviewed_user__id=user_id)
        except Rating.DoesNotExist:
            return Response({'error': 'Rating not found.'}, status=status.HTTP_404_NOT_FOUND)

        rating.delete()
        return Response({'message': 'Rating deleted.'}, status=status.HTTP_204_NO_CONTENT)
    
class GenreListView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        genres = Genre.objects.all()
        serializer = GenreSerializer(genres, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RecentActivityView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        activity = []

        # Books listed
        books = user.books.order_by('-created_at')[:5]
        for book in books:
            activity.append({
                'type': 'book_listed',
                'message': f'You listed "{book.title}" for swap',
                'timestamp': book.created_at,
            })

        # Swaps sent
        sent = user.sent_exchanges.order_by('-created_at')[:5]
        for swap in sent:
            activity.append({
                'type': 'swap_sent',
                'message': f'You sent a swap request for "{swap.offered_book.title}"',
                'timestamp': swap.created_at,
            })

        # Swaps received
        received = user.received_exchanges.order_by('-created_at')[:5]
        for swap in received:
            activity.append({
                'type': 'swap_received',
                'message': f'{swap.requester.name} sent you a swap request for "{swap.requested_book.title}"',
                'timestamp': swap.created_at,
            })

        # Ratings received
        ratings = user.ratings_received.order_by('-created_at')[:5]
        for rating in ratings:
            activity.append({
                'type': 'rating_received',
                'message': f'{rating.reviewer.name} gave you {rating.score}★',
                'timestamp': rating.created_at,
            })

        # Sort all by timestamp, return latest 10
        activity.sort(key=lambda x: x['timestamp'], reverse=True)
        activity = activity[:10]

        # Serialize timestamp
        for item in activity:
            item['timestamp'] = item['timestamp'].isoformat()

        return Response(activity, status=status.HTTP_200_OK)        