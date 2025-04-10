from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class CustomUserManager(BaseUserManager):
    RESTRICTED_USERNAMES = ["admin", "undefined", "null", "superuser", "root", "system"]
    
    def create_user(self, email, password=None, **extra_fields):

        if not email:
            raise ValueError("Users must have an email address.")
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)

        first_name = extra_fields.get("first_name", None)
        last_name = extra_fields.get("last_name", None)

        # Validar y sanitizar el nombre de usuario
        username = extra_fields.get("username", None)
        if username:
            sanitized_username = sanitize_username(username)

            # Verificar si el nombre de usuario está en la lista de restringidos
            if sanitized_username.lower() in self.RESTRICTED_USERNAMES:
                raise ValueError(f"The username '{sanitized_username}' is not allowed.")
            
            user.username = sanitized_username
        
        user.first_name = first_name
        user.last_name = last_name

        username = extra_fields.get("username", None)
        if username and username.lower() in self.RESTRICTED_USERNAMES:
            raise ValueError(f"The username '{username}' is not allowed.")
        
        user.save(using=self._db)

        return user
    
    def create_superuser(self, email, password, **extra_Fields):
        user = self.create_user(email, password, **extra_Fields)
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.role = 'admin'
        user.save(using=self._db)
        return user

class CustomUser(AbstractBaseUser, PermissionsMixin):
    USER_TYPE_CHOICES = [
        ('restaurant', 'Restaurant'),
        ('provider', 'Provider'),
    ]

    id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=100, unique=True)
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['email', 'user_type', 'first_name', 'last_name']

    objects = CustomUserManager()

    def __str__(self):
        return self.email

# restaurant profile
class RestaurantProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    restaurant_name = models.CharField(max_length=255)
    restaurant_ruc = models.CharField(max_length=50)
    restaurant_address = models.TextField()

# Provider profile
class ProviderProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    company_name = models.CharField(max_length=255)
    company_ruc = models.CharField(max_length=50)
    company_address = models.CharField(max_length=255)