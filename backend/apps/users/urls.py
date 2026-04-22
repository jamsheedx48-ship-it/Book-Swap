from django.urls import path
from . import views
urlpatterns = [
    path("register/",views.RegisterView.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("token/refresh/", views.TokenRefreshView.as_view(), name="token_refresh"),
    path('send-otp/', views.SendOTPView.as_view(), name='send-otp'),
    path('verify-otp/', views.VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', views.ResendOTPView.as_view(), name='resend-otp'),
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),
    path('jwt-token/', views.google_jwt_redirect, name='google-jwt'),
    path('mfa/setup/', views.MFASetupView.as_view(), name='mfa-setup'),
    path('mfa/verify-setup/', views.MFAVerifySetupView.as_view(), name='mfa-verify-setup'),
    path('mfa/login-verify/', views.MFALoginVerifyView.as_view(), name='mfa-login-verify'),
    path('mfa/disable/', views.MFADisableView.as_view(), name='mfa-disable'),
    path('mfa/status/', views.MFAStatusView.as_view(), name='mfa-status'),



]