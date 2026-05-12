from django.db import models
from django.conf import settings

class Exchange(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        ACCEPTED = "accepted", "Accepted"
        REJECTED = "rejected", "Rejected"
        COMPLETED = "completed", "Completed"
        CANCELLED = "cancelled", "Cancelled"
    # user who initiates the exchange
    requester = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sent_exchanges",
    )
    # owner of the book being requested
    receiver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="received_exchanges",
    )
    # what the requester offers
    offered_book = models.ForeignKey(
        "books.Book",
        on_delete=models.CASCADE,
        related_name="offered_in_exchanges",
    )
    # what the requester wants
    requested_book = models.ForeignKey(
        "books.Book",
        on_delete=models.CASCADE,
        related_name="requested_in_exchanges",
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )
    message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.requester} → {self.receiver} [{self.status}]"