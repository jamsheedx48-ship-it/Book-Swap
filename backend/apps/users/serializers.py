from rest_framework import serializers
from apps.users.models import User
from django.contrib.auth.password_validation import validate_password
import re
from django.contrib.auth import authenticate
from django.db import IntegrityError


class RegisterSerializer(serializers.ModelSerializer):
    password=serializers.CharField(write_only=True)
    confirm_password=serializers.CharField(write_only=True,required=True)

    class Meta:
        model=User
        fields=['name','email','password','confirm_password']

    def validate_email(self,value):
        value=value.strip().lower()

        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email already exists")
        return value

    def validate_name(self,value):
        value=value.strip()

        if len(value)<2:
            raise serializers.ValidationError("Name must be at least 2 characters")
        
        if not re.fullmatch(r"^[a-zA-Z .'-]+$",value):
            raise serializers.ValidationError("Invalid characters in name")
        
        return value
    
    def validate_password(self,value):
        validate_password(value)
        return value

    def validate(self,attrs):
        if attrs["password"]!=attrs["confirm_password"]:
            raise serializers.ValidationError(
                {"confirm_password":"Passwords do not match"}
            )
        return attrs  
    
    def create(self, validated_data): 
        validated_data.pop("confirm_password")
        try:
            return User.objects.create_user(**validated_data)
        except IntegrityError:
            raise serializers.ValidationError({"email": "Email already registered."}) 
    


class LoginSerializer(serializers.Serializer):
    email=serializers.EmailField()
    password=serializers.CharField(write_only=True)

    def validate_email(self,value):
        return value.strip().lower()

    def validate(self,data):
        email=data.get("email")
        password=data.get("password")

        user=authenticate(username=email,password=password)

        if user is None:
            raise serializers.ValidationError("Invalid credentials")
        if not user.is_active:
            raise serializers.ValidationError("Account is disabled")
        
        data["user"]=user
        return data

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        return value.strip().lower()

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(min_length=6, max_length=6)

    def validate_email(self, value):
        return value.strip().lower()

class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        return value.strip().lower()

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        return value.strip().lower()

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(min_length=6, max_length=6)
    new_password = serializers.CharField(write_only=True)

    def validate_email(self, value):
        return value.strip().lower()

    def validate_new_password(self, value):
        validate_password(value)
        return value    


class MFAVerifySetupSerializer(serializers.Serializer):
    code = serializers.CharField(min_length=6, max_length=6)

class MFALoginVerifySerializer(serializers.Serializer):
    temp_token = serializers.CharField()
    code = serializers.CharField(min_length=6, max_length=6)

class MFADisableSerializer(serializers.Serializer):
    code = serializers.CharField(min_length=6, max_length=6)

class MFAStatusSerializer(serializers.Serializer):
    mfa_enabled = serializers.BooleanField(read_only=True)
