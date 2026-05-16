from django.db import models
from django.conf import settings

class Notification(models.Model):
    TYPES = [
        ('swap_accepted', 'Swap Accepted'),
        ('swap_requested', 'Swap Requested'),
        ('swap_rejected', 'Swap Rejected'),
        ('message', 'New Message'),
    ]

    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=30, choices=TYPES)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']