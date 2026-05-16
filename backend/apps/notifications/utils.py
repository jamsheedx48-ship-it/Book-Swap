from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import Notification

def send_realtime_notification(recipient, notification_type, message):
    print(f"DEBUG: sending to user_id={recipient.id} group=notifications_{recipient.id}")
    notif = Notification.objects.create(
        recipient=recipient,
        notification_type=notification_type,
        message=message,
    )

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f'notifications_{recipient.id}',
        {
            'type': 'send_notification',
            'message': message,
            'notification_type': notification_type,
            'notification_id': notif.id,
        }
    )