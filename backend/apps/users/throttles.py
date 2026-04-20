from rest_framework.throttling import AnonRateThrottle

class LoginThrottle(AnonRateThrottle):
    scope="login"
    rate= '5/min'

class RegisterThrottle(AnonRateThrottle):
    scope="register"
    rate = "3/min"    