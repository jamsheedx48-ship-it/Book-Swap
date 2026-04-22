from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from django.utils import timezone
from datetime import timedelta
import secrets
from encrypted_model_fields.fields import EncryptedCharField

# Create your models here.

class UserManager(BaseUserManager):
    def create_user(self,email,password=None,**extra_fields):
        if not email:
            raise ValueError("Email is required")
        email=self.normalize_email(email)
        user=self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self,email,password=None,**extra_fields):
        extra_fields.setdefault("is_staff",True)
        extra_fields.setdefault("is_superuser",True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True")
    
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True")

        return self.create_user(email=email,password=password,**extra_fields)
    

class User(AbstractBaseUser,PermissionsMixin):
    email=models.EmailField(unique=True)
    name=models.CharField(max_length=255)
    is_active=models.BooleanField(default=True)
    is_staff=models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False) 
    created_at = models.DateTimeField(auto_now_add=True)
    #MFA
    mfa_enabled=models.BooleanField(default=False)
    mfa_secret=EncryptedCharField(max_length=255, null=True, blank=True)

    objects=UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS=["name"]

    def __str__(self):
        return self.email
    

class OTP(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE,related_name='otps')
    code=models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used=models.BooleanField(default=False)

    def save(self,*args,**kwargs):
        if not self.pk:
            self.expires_at=timezone.now()+timedelta(minutes=5)
        super().save(*args,**kwargs)

    def is_valid(self):
        return not self.is_used and timezone.now()<self.expires_at
    
    @staticmethod
    def generate_code():
        return str(secrets.randbelow(900000)+ 100000)
    
    

