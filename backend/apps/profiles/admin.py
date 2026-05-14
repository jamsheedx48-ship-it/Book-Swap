from django.contrib import admin
from .models import Rating,UserProfile,Genre
# Register your models here.

admin.site.register(Rating)
admin.site.register(UserProfile)
admin.site.register(Genre)
