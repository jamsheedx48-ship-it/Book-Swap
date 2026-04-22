from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import SessionAuthentication
from .serializers import (
    RegisterSerializer, LoginSerializer, LogoutSerializer,
    SendOTPSerializer, VerifyOTPSerializer, ResendOTPSerializer,
    ForgotPasswordSerializer, ResetPasswordSerializer,
    MFAVerifySetupSerializer, MFALoginVerifySerializer,
    MFADisableSerializer, MFAStatusSerializer
)
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .throttles import LoginThrottle, RegisterThrottle, OTPSendThrottle, OTPVerifyThrottle
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import get_user_model
from .models import OTP
from django.core.mail import send_mail
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from drf_spectacular.utils import extend_schema
import pyotp
import qrcode
import base64
from io import BytesIO
import secrets
from django.core.cache import cache
import hmac


User = get_user_model()


class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [RegisterThrottle]
    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        code = OTP.generate_code()
        OTP.objects.create(user=user, code=code)
        send_mail(
            subject='Verify your email',
            message=f'Your OTP is: {code}\nValid for 5 minutes.',
            from_email=None,
            recipient_list=[user.email],
        )

        return Response(
            {
                "message": "User registered successfully. OTP sent to your email.",
                "data": {"id": user.id, "email": user.email, "name": user.name}
            },
            status=status.HTTP_201_CREATED
        )


class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginThrottle]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data.get("user")

        if not user.is_verified:
            return Response(
                {'error': 'Email not verified. Please verify your OTP first.'},
                status=status.HTTP_403_FORBIDDEN
            )
        if user.mfa_enabled:
            temp_token=secrets.token_hex(32)
            cache.set(f"mfa_temp_{temp_token}",user.id,timeout=300)
            return Response({
                "mfa_required":True,
                "temp_token":temp_token
            },status=status.HTTP_200_OK)

        refresh = RefreshToken.for_user(user)
        response= Response({
            "message":"Login successful",
            "email":user.email,
            "name":user.name,
        },status=status.HTTP_200_OK)

        response.set_cookie(
            key='access_token',
            value=str(refresh.access_token),
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age=60*60,
        )
        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age=24*60*60
        )
        return response
    
class TokenRefreshView(APIView):
    permission_classes=[AllowAny]

    def post(self,request):
        refresh_token=request.COOKIES.get("refresh_token")
        if not refresh_token:
            return Response({"error": "Refresh token not found"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            token=RefreshToken(refresh_token)
            access_token=str(token.access_token)
        except TokenError:
            return Response({"error": "Invalid or expired refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

        response=Response({"message": "Token refreshed"}, status=status.HTTP_200_OK)
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age= 60*60
        )
        return response
    

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token=request.COOKIES.get("refresh_token")

        if not refresh_token:
            return Response({"error": "Refresh token not found"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)
        
        response=Response({"message": "Logged out successfully"}, status=status.HTTP_205_RESET_CONTENT)
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response


class SendOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPSendThrottle]
    serializer_class = SendOTPSerializer

    
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        OTP.objects.filter(user=user, is_used=False).update(is_used=True)
        code = OTP.generate_code()
        OTP.objects.create(user=user, code=code)
        send_mail(
            subject='Your OTP Code',
            message=f'Your OTP is: {code}\n Valid for 5 minutes. Do not share it with anyone.',
            from_email=None,
            recipient_list=[email],
        )
        return Response({'message': 'OTP sent to your email'}, status=status.HTTP_200_OK)


class VerifyOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPVerifyThrottle]
    serializer_class = VerifyOTPSerializer


    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        code = serializer.validated_data['code']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            otp = OTP.objects.filter(user=user,  is_used=False).latest('created_at')
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not hmac.compare_digest(otp.code, code):
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if not otp.is_valid():
            return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

        otp.is_used = True
        otp.save()
        user.is_verified = True
        user.save()

        return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)


class ResendOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPSendThrottle]
    serializer_class = ResendOTPSerializer

    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        if user.is_verified:
            return Response({'error': 'User already verified'}, status=status.HTTP_400_BAD_REQUEST)

        last_otp = OTP.objects.filter(user=user).order_by('-created_at').first()
        if last_otp:
            cooldown = timezone.now() - last_otp.created_at
            if cooldown.total_seconds() < 60:
                wait = 60 - cooldown.seconds
                return Response(
                    {'error': f'Please wait {wait} seconds before resending.'},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )

        OTP.objects.filter(user=user, is_used=False).update(is_used=True)
        code = OTP.generate_code()
        OTP.objects.create(user=user, code=code)
        send_mail(
            subject='Your new OTP Code',
            message=f'Your new OTP is: {code}\nValid for 5 minutes.',
            from_email=None,
            recipient_list=[email],
        )
        return Response({'message': 'OTP resent successfully'}, status=status.HTTP_200_OK)


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPSendThrottle]
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        if not user.is_verified:
            return Response(
                {'error': 'Email not verified. Please verify your account first.'},
                status=status.HTTP_403_FORBIDDEN
            )

        last_otp = OTP.objects.filter(user=user).order_by('-created_at').first()
        if last_otp:
            cooldown = timezone.now() - last_otp.created_at
            if cooldown.total_seconds() < 60:
                wait = 60 - cooldown.seconds
                return Response(
                    {'error': f'Please wait {wait} seconds before retrying.'},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )

        OTP.objects.filter(user=user, is_used=False).update(is_used=True)
        code = OTP.generate_code()
        OTP.objects.create(user=user, code=code)
        send_mail(
            subject='Password Reset OTP',
            message=f'Your password reset OTP is: {code}\nValid for 5 minutes.',
            from_email=None,
            recipient_list=[email],
        )
        return Response({'message': 'Password reset OTP sent to your email'}, status=status.HTTP_200_OK)


class ResetPasswordView(APIView):

    permission_classes = [AllowAny]
    throttle_classes = [OTPVerifyThrottle]
    serializer_class=ResetPasswordSerializer

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        code = serializer.validated_data['code']
        new_password = serializer.validated_data['new_password'] 

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            otp = OTP.objects.filter(user=user, is_used=False).latest('created_at')
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not hmac.compare_digest(otp.code, code):
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not otp.is_valid():
            return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

        otp.is_used = True
        otp.save()
        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)


@extend_schema(request=None)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([SessionAuthentication])
def google_jwt_redirect(request):
    user = request.user

    if not user.is_active:
        return Response({'error': 'Account is disabled'}, status=status.HTTP_403_FORBIDDEN)

    created = not bool(user.name)
    if not user.name:
        user.name = user.email.split('@')[0]
        user.save()
    refresh = RefreshToken.for_user(user)
    return Response({
        'access': str(refresh.access_token),
        'refresh': str(refresh),
        'user': user.email,
        'created': created
    })


class MFASetupView(APIView):
    permission_classes=[IsAuthenticated]
    
    @extend_schema(request=None)
    def post(self,request):
        user=request.user
        if user.mfa_enabled:
            return Response({"detail":"MFA is already enabled"},status=status.HTTP_400_BAD_REQUEST)
        secret=pyotp.random_base32()
        user.mfa_secret=secret
        user.save()

        totp=pyotp.TOTP(secret)
        uri=totp.provisioning_uri(name=user.email,issuer_name="BookSwap")
        
        qr=qrcode.make(uri)
        buffer=BytesIO()
        qr.save(buffer,format="PNG")
        qr_base64=base64.b64encode(buffer.getvalue()).decode()

        return Response({
            "secret":secret,
            "qr_code":f"data:image/png;base64,{qr_base64}"
        })

class MFAVerifySetupView(APIView):
    permission_classes=[IsAuthenticated]
    serializer_class = MFAVerifySetupSerializer

    def post(self,request):
        serializer = MFAVerifySetupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        code = serializer.validated_data['code']
        
        if not user.mfa_secret:
            return Response({"detail": "MFA setup not initiated."}, status=status.HTTP_400_BAD_REQUEST)

        totp=pyotp.TOTP(user.mfa_secret)
        if not totp.verify(code):
            return Response({"detail": "Invalid code."}, status=status.HTTP_400_BAD_REQUEST)
        
        user.mfa_enabled=True
        user.save()
        return Response({"detail": "MFA enabled successfully."})


class MFALoginVerifyView(APIView):
    permission_classes=[AllowAny]
    serializer_class = MFALoginVerifySerializer

    def post(self,request):
        serializer = MFALoginVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        temp_token = serializer.validated_data['temp_token']
        code = serializer.validated_data['code']
        
        
        user_id=cache.get(f"mfa_temp_{temp_token}")
        if not user_id:
            return Response({"detail": "Session expired or invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error":"user not found"},status=status.HTTP_400_BAD_REQUEST)    
        
        totp=pyotp.TOTP(user.mfa_secret)
        if not totp.verify(code):
            return Response({"detail": "Invalid MFA code."}, status=status.HTTP_400_BAD_REQUEST)
        
        cache.delete(f"mfa_temp_{temp_token}")
        refresh=RefreshToken.for_user(user)
        
        response = Response({
            "message": "Login successful",
            "email": user.email,
            "name": user.name,
        }, status=status.HTTP_200_OK)

        response.set_cookie(
            key='access_token',
            value=str(refresh.access_token),
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age=60 * 60,
        )
        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age=24 * 60 * 60,
        )
        return response


class MFADisableView(APIView):
    permission_classes=[IsAuthenticated]
    serializer_class = MFADisableSerializer

    def post(self,request):
        serializer = MFADisableSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        code = serializer.validated_data['code']

        if not user.mfa_enabled:
            return Response({"detail": "MFA is not enabled."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not user.mfa_secret:
            return Response({"detail": "MFA not set up."}, status=status.HTTP_400_BAD_REQUEST)
        
        totp=pyotp.TOTP(user.mfa_secret)
        if not totp.verify(code):
            return Response({"detail": "Invalid code"}, status=status.HTTP_400_BAD_REQUEST)
        
        user.mfa_enabled=False
        user.mfa_secret=None
        user.save()

        return Response({"detail": "MFA disabled successfully"})
    
class MFAStatusView(APIView):
    permission_classes=[IsAuthenticated]
    serializer_class = MFAStatusSerializer

    def get(self, request):
        return Response({"mfa_enabled": request.user.mfa_enabled})
