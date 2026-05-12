import boto3
import json
import logging
from django.conf import settings
logger = logging.getLogger(__name__)

sqs = boto3.client("sqs", region_name=settings.AWS_REGION)

QUEUE_URL = settings.SQS_NOTIFICATION_QUEUE_URL


def send_notification(notification_type: str, fcm_token: str, payload: dict):
    print(f"DEBUG: send_notification called - type={notification_type} token={fcm_token}")
    if not fcm_token:
        logger.warning(f"No FCM token for notification type: {notification_type}")
        return

    message = {
        "type": notification_type,
        "fcm_token": fcm_token,
        "payload": payload,
    }
    try:
        sqs.send_message(
            QueueUrl=QUEUE_URL,
            MessageBody=json.dumps(message),
        )
        logger.info(f"SQS message sent: {notification_type}")
    except Exception as e:
        print(f"SQS ERROR: {e}")
        logger.error(f"SQS send failed: {e}")