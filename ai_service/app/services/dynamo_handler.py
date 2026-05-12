import os
import boto3
from datetime import datetime, timezone

dynamodb = boto3.resource(
    "dynamodb",
    region_name=os.getenv("AWS_REGION", "ap-south-1"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
)

TABLE_NAME = os.getenv("DYNAMODB_TABLE", "rag_chat_history")
table = dynamodb.Table(TABLE_NAME)


def get_conversation_id(user_id: str, book_id: int) -> str:
    return f"{book_id}_{user_id}"


def get_chat_history(user_id: str, book_id: int) -> list:
    try:
        response = table.get_item(
            Key={
                "user_id": user_id,
                "conversation_id": get_conversation_id(user_id, book_id),
            }
        )
        item = response.get("Item")
        if item:
            return item.get("messages", [])
        return []
    except Exception as e:
        print(f"DynamoDB get error: {e}")
        return []


def save_message(user_id: str, book_id: int, book_title: str, role: str, text: str):
    try:
        conversation_id = get_conversation_id(user_id, book_id)
        now = datetime.now(timezone.utc).isoformat()

        new_message = {
            "role": role,
            "text": text,
            "timestamp": now,
        }

        response = table.get_item(
            Key={
                "user_id": user_id,
                "conversation_id": conversation_id,
            }
        )
        item = response.get("Item")

        if item:
            messages = item.get("messages", [])
            messages.append(new_message)
            table.update_item(
                Key={
                    "user_id": user_id,
                    "conversation_id": conversation_id,
                },
                UpdateExpression="SET messages = :m, updated_at = :u",
                ExpressionAttributeValues={
                    ":m": messages,
                    ":u": now,
                },
            )
        else:
            table.put_item(
                Item={
                    "user_id": user_id,
                    "conversation_id": conversation_id,
                    "book_id": book_id,
                    "book_title": book_title,
                    "messages": [new_message],
                    "created_at": now,
                    "updated_at": now,
                }
            )
    except Exception as e:
        print(f"DynamoDB save error: {e}")