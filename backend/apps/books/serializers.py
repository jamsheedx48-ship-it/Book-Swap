from rest_framework import serializers
from .models import Book,Category


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model=Category
        fields=['id','name']

class BookSerializer(serializers.ModelSerializer):
    user=serializers.StringRelatedField(read_only=True)
    category_detail=CategorySerializer(source='category',read_only=True)
    class Meta:
        model=Book
        fields=[
            'id','user',
            'title','author',
            'category','category_detail',
            'condition','description',
            'image','created_at'
        ]
        read_only_fields = ['id', 'user', 'created_at']
