from django.db import models
from django.conf import settings
# Create your models here.


class Genre(models.Model):
    GENRE_CHOICES = [
        ('literary_fiction', 'Literary Fiction'),
        ('science_fiction', 'Science Fiction'),
        ('fantasy', 'Fantasy'),
        ('mystery', 'Mystery'),
        ('thriller', 'Thriller'),
        ('romance', 'Romance'),
        ('horror', 'Horror'),
        ('history', 'History'),
        ('biography', 'Biography'),
        ('self_help', 'Self Help'),
        ('philosophy', 'Philosophy'),
        ('science', 'Science'),
        ('technology', 'Technology'),
        ('poetry', 'Poetry'),
        ('comics', 'Comics & Graphic Novels'),
    ]

    name = models.CharField(max_length=50, choices=GENRE_CHOICES, unique=True)

    def __str__(self):
        return self.get_name_display()

class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True)
    interests = models.ManyToManyField(Genre, blank=True, related_name='users')
    location = models.CharField(max_length=100, blank=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    avatar_url = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.name}'s profile"

    @property
    def total_books_listed(self):
        return self.user.books.count()

    @property
    def total_swaps_done(self):
        return self.user.sent_exchanges.filter(status='completed').count() + \
               self.user.received_exchanges.filter(status='completed').count()

    @property
    def average_rating(self):
        ratings = self.user.ratings_received.all()
        if not ratings.exists():
            return None
        return round(sum(r.score for r in ratings) / ratings.count(), 1)


class Rating(models.Model):
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='ratings_given')
    reviewed_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='ratings_received')
    score = models.PositiveSmallIntegerField()  # 1 to 5
    comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('reviewer', 'reviewed_user')  # one rating per user pair
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.reviewer.name} → {self.reviewed_user.name}: {self.score}★"
    
