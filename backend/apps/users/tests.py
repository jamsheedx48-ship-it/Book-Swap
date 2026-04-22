from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from apps.users.views import LoginView,RegisterView,LogoutView,SendOTPView,VerifyOTPView,ResendOTPView,ForgotPasswordView,ResetPasswordView,MFASetupView,MFAVerifySetupView,MFALoginVerifyView,MFADisableView,MFAStatusView
from rest_framework_simplejwt.tokens import RefreshToken
from apps.users.models import OTP
import pyotp
from django.core.cache import cache

User = get_user_model()

RegisterView.throttle_classes = []
LoginView.throttle_classes = []
LogoutView.throttle_classes = []
SendOTPView.throttle_classes = []
VerifyOTPView.throttle_classes = []
ResendOTPView.throttle_classes = []
ForgotPasswordView.throttle_classes=[]
ResetPasswordView.throttle_classes=[]
MFASetupView.throttle_classes = []
MFAVerifySetupView.throttle_classes = []
MFALoginVerifyView.throttle_classes = []
MFADisableView.throttle_classes = []
MFAStatusView.throttle_classes = []




class RegisterViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("register")
        self.valid_data = {
            "name": "Jamsheed",
            "email": "jamsheed@example.com",
            "password": "StrongPass@123",
            "confirm_password": "StrongPass@123",
        }

    def test_register_success(self):
        response = self.client.post(self.url, self.valid_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_register_duplicate_email(self):
        self.client.post(self.url, self.valid_data, format="json")
        response = self.client.post(self.url, self.valid_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_missing_fields(self):
        response = self.client.post(self.url, {"name": "Jamsheed"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class LoginViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("login")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )
        self.user.is_verified = True
        self.user.save()

    def test_login_success(self):
        response = self.client.post(self.url, {
            "email": "jamsheed@example.com",
            "password": "StrongPass@123",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_login_wrong_password(self):
        response = self.client.post(self.url, {
            "email": "jamsheed@example.com",
            "password": "WrongPass@123",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_unverified_user(self):
        self.user.is_verified = False
        self.user.save()
        response = self.client.post(self.url, {
            "email": "jamsheed@example.com",
            "password": "StrongPass@123",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

class LogoutViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("logout")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )
        self.user.is_verified = True
        self.user.save()
        refresh = RefreshToken.for_user(self.user)
        self.refresh_token = str(refresh)
        self.access_token = str(refresh.access_token)

    def test_logout_success(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        response = self.client.post(self.url, {"refresh": self.refresh_token}, format="json")
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)

    def test_logout_invalid_token(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        response = self.client.post(self.url, {"refresh": "invalidtoken"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_without_auth(self):
        response = self.client.post(self.url, {"refresh": self.refresh_token}, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

class SendOTPViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("send-otp")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )

    def test_send_otp_success(self):
        response = self.client.post(self.url, {"email": "jamsheed@example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_send_otp_user_not_found(self):
        response = self.client.post(self.url, {"email": "notfound@example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_send_otp_missing_email(self):
        response = self.client.post(self.url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class VerifyOTPViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("verify-otp")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )
        self.otp = OTP.objects.create(user=self.user, code=OTP.generate_code())

    def test_verify_otp_success(self):
        response = self.client.post(self.url, {
            "email": "jamsheed@example.com",
            "code": self.otp.code,
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_verified)

    def test_verify_otp_wrong_code(self):
        response = self.client.post(self.url, {
            "email": "jamsheed@example.com",
            "code": "000000",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_otp_user_not_found(self):
        response = self.client.post(self.url, {
            "email": "notfound@example.com",
            "code": "123456",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class ResendOTPViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("resend-otp")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )

    def test_resend_otp_success(self):
        response = self.client.post(self.url, {"email": "jamsheed@example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_resend_otp_already_verified(self):
        self.user.is_verified = True
        self.user.save()
        response = self.client.post(self.url, {"email": "jamsheed@example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_resend_otp_user_not_found(self):
        response = self.client.post(self.url, {"email": "notfound@example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

class ForgotPasswordViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("forgot-password")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )
        self.user.is_verified = True
        self.user.save()

    def test_forgot_password_success(self):
        response = self.client.post(self.url, {"email": "jamsheed@example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_forgot_password_user_not_found(self):
        response = self.client.post(self.url, {"email": "notfound@example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_forgot_password_unverified_user(self):
        self.user.is_verified = False
        self.user.save()
        response = self.client.post(self.url, {"email": "jamsheed@example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class ResetPasswordViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("reset-password")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )
        self.user.is_verified = True
        self.user.save()
        self.otp = OTP.objects.create(user=self.user, code=OTP.generate_code())

    def test_reset_password_success(self):
        response = self.client.post(self.url, {
            "email": "jamsheed@example.com",
            "code": self.otp.code,
            "new_password": "NewStrongPass@123",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_reset_password_wrong_code(self):
        response = self.client.post(self.url, {
            "email": "jamsheed@example.com",
            "code": "000000",
            "new_password": "NewStrongPass@123",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_reset_password_user_not_found(self):
        response = self.client.post(self.url, {
            "email": "notfound@example.com",
            "code": "123456",
            "new_password": "NewStrongPass@123",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_reset_password_actually_changes(self):
        self.client.post(self.url, {
            "email": "jamsheed@example.com",
            "code": self.otp.code,
            "new_password": "NewStrongPass@123",
        }, format="json")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewStrongPass@123"))


class MFASetupViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("mfa-setup")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )
        self.user.is_verified = True
        self.user.save()
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {str(refresh.access_token)}")

    def test_mfa_setup_success(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("secret", response.data)
        self.assertIn("qr_code", response.data)

    def test_mfa_setup_already_enabled(self):
        self.user.mfa_enabled = True
        self.user.save()
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_mfa_setup_requires_auth(self):
        self.client.credentials()
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class MFAVerifySetupViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("mfa-verify-setup")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )
        self.user.is_verified = True
        self.user.mfa_secret = pyotp.random_base32()
        self.user.save()
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {str(refresh.access_token)}")

    def test_verify_setup_success(self):
        code = pyotp.TOTP(self.user.mfa_secret).now()
        response = self.client.post(self.url, {"code": code}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.mfa_enabled)

    def test_verify_setup_invalid_code(self):
        response = self.client.post(self.url, {"code": "000000"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class MFALoginVerifyViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("mfa-login-verify")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )
        self.user.is_verified = True
        self.user.mfa_enabled = True
        self.user.mfa_secret = pyotp.random_base32()
        self.user.save()
        self.temp_token = "testtemptoken123"
        cache.set(f"mfa_temp_{self.temp_token}", self.user.id, timeout=300)

    def test_mfa_login_verify_success(self):
        code = pyotp.TOTP(self.user.mfa_secret).now()
        response = self.client.post(self.url, {
            "temp_token": self.temp_token,
            "code": code,
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    def test_mfa_login_verify_invalid_code(self):
        response = self.client.post(self.url, {
            "temp_token": self.temp_token,
            "code": "000000",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_mfa_login_verify_expired_token(self):
        code = pyotp.TOTP(self.user.mfa_secret).now()
        response = self.client.post(self.url, {
            "temp_token": "expiredtoken",
            "code": code,
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class MFADisableViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("mfa-disable")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )
        self.user.is_verified = True
        self.user.mfa_enabled = True
        self.user.mfa_secret = pyotp.random_base32()
        self.user.save()
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {str(refresh.access_token)}")

    def test_mfa_disable_success(self):
        code = pyotp.TOTP(self.user.mfa_secret).now()
        response = self.client.post(self.url, {"code": code}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_enabled)

    def test_mfa_disable_invalid_code(self):
        response = self.client.post(self.url, {"code": "000000"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_mfa_disable_not_enabled(self):
        self.user.mfa_enabled = False
        self.user.save()
        code = pyotp.TOTP(self.user.mfa_secret).now()
        response = self.client.post(self.url, {"code": code}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class MFAStatusViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("mfa-status")
        self.user = User.objects.create_user(
            name="Jamsheed",
            email="jamsheed@example.com",
            password="StrongPass@123",
        )
        self.user.is_verified = True
        self.user.save()
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {str(refresh.access_token)}")

    def test_mfa_status_disabled(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["mfa_enabled"])

    def test_mfa_status_enabled(self):
        self.user.mfa_enabled = True
        self.user.save()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["mfa_enabled"])

    def test_mfa_status_requires_auth(self):
        self.client.credentials()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
