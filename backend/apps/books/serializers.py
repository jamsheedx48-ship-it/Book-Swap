from rest_framework import serializers
from .models import Book,Category


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model=Category
        fields=['id','name']

class BookSerializer(serializers.ModelSerializer):
    user=serializers.StringRelatedField(read_only=True)
    user_id=serializers.IntegerField(source='user.id',read_only=True)
    category_detail=CategorySerializer(source='category',read_only=True)
    class Meta:
        model=Book
        fields=[
            'id','user','user_id',
            'title','author',
            'category','category_detail',
            'condition','description',
            'long_description',
            'image','image_thumbnail', 'image_detail','created_at'
        ]
        read_only_fields = ['id', 'user','user_id', 'created_at', 'image_thumbnail', 'image_detail','long_description']
