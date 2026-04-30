from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model
from http.cookies import SimpleCookie

User = get_user_model()


@database_sync_to_async
def get_user_from_token(token_key):
    try:
        token = AccessToken(token_key)
        user_id = token["user_id"]
        return User.objects.get(id=user_id)
    except Exception:
        return AnonymousUser()


class JWTAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        cookies = {}
        for header_name, header_value in scope.get("headers", []):
            if header_name == b"cookie":
                cookie = SimpleCookie(header_value.decode())
                cookies = {k: v.value for k, v in cookie.items()}
                break

        print("COOKIES FOUND:", cookies)
        token = cookies.get("access_token", None)
        print("TOKEN:", token)

        if token:
            scope["user"] = await get_user_from_token(token)
        else:
            scope["user"] = AnonymousUser()

        return await super().__call__(scope, receive, send)