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

    conversation = models.OneToOneField(
    'chat.Conversation',
    on_delete=models.SET_NULL,
    null=True,
    blank=True,
    related_name='exchange',
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.requester} → {self.receiver} [{self.status}]"
    

class MeetupDetail(models.Model):
    exchange = models.OneToOneField(
        Exchange, on_delete=models.CASCADE, related_name='meetup'
    )
    location = models.CharField(max_length=255)
    meetup_date = models.DateTimeField()
    notes = models.TextField(blank=True)
    proposed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='proposed_meetups'
    )
    confirmed = models.BooleanField(default=False)

    def __str__(self):
        return f"Meetup for Exchange #{self.exchange_id} at {self.location}"