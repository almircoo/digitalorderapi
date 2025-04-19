import uuid

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken

import re

def sanitize_username(username):
    """Sanitize username by removing special characters and spaces"""
    return re.sub(r'[^\w\.]', '', username)


class CustomUserManager(BaseUserManager):
    RESTRICTED_USERNAMES = ["admin", "undefined", "null", "superuser", "root", "system"]
    
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address.")
            
        email = self.normalize_email(email)
        
        # Validate and sanitize username
        username = extra_fields.get("username", None)
        if username:
            sanitized_username = sanitize_username(username)
            # Check if username is in restricted list
            if sanitized_username.lower() in self.RESTRICTED_USERNAMES:
                raise ValueError(f"The username '{sanitized_username}' is not allowed.")
            extra_fields["username"] = sanitized_username
        
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
        
    def create_superuser(self, email, password, **extra_fields):
        if password is None:
            raise TypeError('Password should not be none')
            
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_active', True)
        
        user = self.create_user(email, password, **extra_fields)
        return user

class CustomUser(AbstractBaseUser, PermissionsMixin):
    USER_TYPE_CHOICES = [
        ('restaurant', 'Restaurant'),
        ('provider', 'Provider'),
        ('admin', 'admin'),
    ]

    id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=100, unique=True)
    role = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, default="restaurant")
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'role']

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

# restaurant profile
class RestaurantProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    restaurant_name = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20)
    restaurant_ruc = models.CharField(max_length=50)
    

    def __str__(self):
        return self.restaurant_name

# Provider profile
class ProviderProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    company_name = models.CharField(max_length=255)
    provider_category = models.CharField(max_length=255)
    contact_number = models.CharField(max_length=20)
    company_ruc = models.CharField(max_length=50)
    location = models.CharField(max_length=255)

    def __str__(self):
        return self.company_name