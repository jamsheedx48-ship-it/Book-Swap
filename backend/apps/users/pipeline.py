from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.shortcuts import redirect
from django.conf import settings
from django.contrib.auth import logout


def generate_jwt_and_redirect(backend, user, response, *args, **kwargs):
    print("=== PIPELINE CALLED ===")
    print("USER:", user)
    print("USER NAME:", user.name)
    request = backend.strategy.request

    # Save Google name if user has no name
    if not user.name:
        details = kwargs.get('details', {})
        google_name = details.get('fullname') or details.get('first_name', '')
        user.name = google_name or user.email.split('@')[0]
        user.save()

    # Blacklist old refresh token if exists
    old_refresh = request.COOKIES.get('refresh_token')
    if old_refresh:
        try:
            token = RefreshToken(old_refresh)
            token.blacklist()
        except TokenError:
            pass

    logout(request)

    refresh = RefreshToken.for_user(user)

    redirect_response = redirect(f"{settings.FRONTEND_URL}/oauth/callback")

    redirect_response.delete_cookie('access_token', samesite='Lax')
    redirect_response.delete_cookie('refresh_token', samesite='Lax')

    redirect_response.set_cookie(
        key='access_token',
        value=str(refresh.access_token),
        httponly=True,
        secure=False,
        samesite='Lax',
        max_age=60*60,
    )
    redirect_response.set_cookie(
        key='refresh_token',
        value=str(refresh),
        httponly=True,
        secure=False,
        samesite='Lax',
        max_age=24*60*60,
    )

    return redirect_response