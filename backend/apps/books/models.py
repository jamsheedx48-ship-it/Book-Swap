from django.db import models
from django.conf import settings
# Create your models here.

class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = 'Categories'

class Book(models.Model):
    class Condition(models.TextChoices):
        NEW = 'new', 'New'
        GOOD = 'good', 'Good'
        FAIR = 'fair', 'Fair'

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='books'
    )
    title = models.CharField(max_length=255)
    author = models.CharField(max_length=255)
    category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='books'
    )
    condition = models.CharField(
        max_length=10,
        choices=Condition.choices,
        default=Condition.GOOD
    )
    description = models.TextField(blank=True)
    image = models.ImageField(upload_to='books/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} by {self.author}"
