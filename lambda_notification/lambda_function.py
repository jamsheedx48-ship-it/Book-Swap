import json
import boto3
import firebase_admin
from firebase_admin import credentials, messaging

secrets_client = boto3.client("secretsmanager", region_name="ap-south-1")


def get_firebase_credentials():
    secret = secrets_client.get_secret_value(SecretId="firebase/bookswap/service-account")
    return json.loads(secret["SecretString"])


def init_firebase():
    if not firebase_admin._apps:
        cred_dict = get_firebase_credentials()
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)


NOTIFICATION_TEMPLATES = {
    "REQUEST_RECEIVED": {
        "title": "New Swap Request",
        "body": lambda p: f"{p['requester_name']} wants to swap '{p['book_title']}'",
    },
    "REQUEST_ACCEPTED": {
        "title": "Request Accepted! 🎉",
        "body": lambda p: f"Your request for '{p['book_title']}' was accepted.",
    },
    "REQUEST_REJECTED": {
        "title": "Request Rejected",
        "body": lambda p: f"Your request for '{p['book_title']}' was rejected.",
    },
}


def lambda_handler(event, context):
    init_firebase()

    for record in event["Records"]:
        body = json.loads(record["body"])
        notification_type = body["type"]
        fcm_token = body["fcm_token"]
        payload = body["payload"]

        template = NOTIFICATION_TEMPLATES.get(notification_type)
        if not template:
            print(f"Unknown notification type: {notification_type}")
            continue

        message = messaging.Message(
            notification=messaging.Notification(
                title=template["title"],
                body=template["body"](payload),
            ),
            data={k: str(v) for k, v in payload.items()},
            token=fcm_token,
        )

        try:
            response = messaging.send(message)
            print(f"Notification sent: {response}")
        except Exception as e:
            print(f"FCM failed for token {fcm_token}: {e}")
            raise