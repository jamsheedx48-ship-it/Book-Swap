from rest_framework.views import APIView
from rest_framework.permissions import AllowAny,IsAuthenticated
from .serializers import RegisterSerializer,LoginSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .throttles import LoginThrottle,RegisterThrottle
from rest_framework_simplejwt.exceptions import TokenError

# Create your views here.

class RegisterView(APIView):
    permission_classes=[AllowAny]
    throttle_classes=[RegisterThrottle]

    def post(self,request):
        serializer=RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user=serializer.save()
        return Response(
            {
                "message":"User registered successfully",
                "data":{
                    "id":user.id,
                    "email":user.email,
                    "name":user.name
                }
            },
            status=status.HTTP_201_CREATED
        )

class LoginView(APIView):
    permission_classes=[AllowAny]
    throttle_classes=[LoginThrottle]

    def post(self,request):
        serializer=LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user=serializer.validated_data.get("user")
        refresh = RefreshToken.for_user(user)

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "email": user.email,
            "name": user.name,
        }, status=status.HTTP_200_OK)
    
class LogoutView(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request):
        try:
            refresh_token=request.data["refresh"]
            token=RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"message":"Logged out successfully"},status=status.HTTP_205_RESET_CONTENT
            )
        except KeyError:
            return Response({"error": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError:
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        
    