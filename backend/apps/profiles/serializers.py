from rest_framework import serializers
from .models import UserProfile,Rating,Genre


class GenreSerializer(serializers.ModelSerializer):
    label = serializers.CharField(source='get_name_display', read_only=True)

    class Meta:
        model = Genre
        fields = ['id', 'name', 'label']

class UserProfilePublicSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='user.name', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    total_books_listed = serializers.IntegerField(read_only=True)
    total_swaps_done = serializers.IntegerField(read_only=True)
    average_rating = serializers.FloatField(read_only=True)
    interests = GenreSerializer(many=True, read_only=True)
    avatar_display = serializers.SerializerMethodField()

    def get_avatar_display(self, obj):
        if obj.avatar_url:
            return obj.avatar_url
        if obj.avatar:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.avatar.url)
            return obj.avatar.url
        return None

    class Meta:
        model = UserProfile
        fields = [
            'id', 'name', 'email',
            'bio', 'location', 'avatar','avatar_url','avatar_display',
            'interests',
            'total_books_listed', 'total_swaps_done', 'average_rating',
            'created_at',
        ]


class UserProfileEditSerializer(serializers.ModelSerializer):
    avatar_url = serializers.URLField(write_only=True, required=False) # New field

    interests = serializers.PrimaryKeyRelatedField(
        queryset=Genre.objects.all(),
        many=True,
        required=False
    )

    class Meta:
        model = UserProfile
        fields = ['bio', 'location', 'avatar','interests','avatar_url']

    def update(self, instance, validated_data):
        avatar_url = validated_data.pop('avatar_url', None)
        if avatar_url:
            instance.avatar = None
            instance.avatar_url = avatar_url
            instance.save()
        elif avatar_url == '':
            instance.avatar_url = None  # clear cartoon when real photo uploaded
            instance.save()
        return super().update(instance, validated_data)

        
        return super().update(instance, validated_data)    


class RatingSerializer(serializers.ModelSerializer):
    reviewer_name = serializers.CharField(source='reviewer.name', read_only=True)

    class Meta:
        model = Rating
        fields = ['id', 'reviewer_name', 'score', 'comment', 'created_at']
        read_only_fields = ['id', 'reviewer_name', 'created_at']