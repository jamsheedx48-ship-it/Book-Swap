from rest_framework.throttling import AnonRateThrottle

class LoginThrottle(AnonRateThrottle):
    scope="login"

class RegisterThrottle(AnonRateThrottle):
    scope="register"

class OTPSendThrottle(AnonRateThrottle):
    scope = 'otp_send'

class OTPVerifyThrottle(AnonRateThrottle):
    scope = 'otp_verify'
