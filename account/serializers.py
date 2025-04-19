from rest_framework import serializers
from django.contrib import auth
from .models import CustomUser, RestaurantProfile, ProviderProfile
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=128, min_length=6, write_only=True)
    password_confirmation = serializers.CharField(max_length=128, min_length=6, write_only=True)
    
    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'password', 'password_confirmation', 'first_name', 'last_name', 'role']
    
    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')
        password = attrs.get('password', '')
        password_confirmation = attrs.get('password_confirmation', '')
        
        if not username.isalnum():
            raise serializers.ValidationError('Username should only contain alphanumeric characters')
        
        if password != password_confirmation:
            raise serializers.ValidationError({'password': 'Passwords must match'})
            
        return attrs
    
    def create(self, validated_data):
        # Remove password_confirmation from the data
        validated_data.pop('password_confirmation', None)
        
        # Create user with create_user method
        return CustomUser.objects.create_user(**validated_data)

class RestaurantProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = RestaurantProfile
        fields = ['restaurant_name', 'address', 'phone_number', 'restaurant_ruc']

class ProviderProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProviderProfile
        fields = ['company_name', 'provider_category', 'contact_number', 'company_ruc', 'location']

# class LoginSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(max_length=255)
#     password = serializers.CharField(max_length=128, min_length=6, write_only=True)
#     username = serializers.CharField(max_length=255, read_only=True)
#     tokens = serializers.SerializerMethodField()
#     role = serializers.ChoiceField(choices=['restaurant', 'provider'])
    
#     def get_tokens(self, obj):
#         user = CustomUser.objects.get(email=obj['email'])
#         return {
#             'refresh': user.tokens()['refresh'],
#             'access': user.tokens()['access']
#         }
#         # user.tokens()
    
#     class Meta:
#         model = CustomUser
#         fields = ['email', 'password', 'username', 'tokens', 'role']
    
#     def validate(self, attrs):
#         email = attrs.get('email', '')
#         password = attrs.get('password', '')
#         role = attrs.get('role', '')
#         filtered_user_by_email = CustomUser.objects.filter(email=email)
#         user = auth.authenticate(email=email, password=password)
        
#         # if filtered_user_by_email.exists() and filtered_user_by_email[0].auth_provider != 'email':
#         #     raise AuthenticationFailed(
#         #         detail='Please continue your login using ' + filtered_user_by_email[0].auth_provider)

#         if not user:
#             raise serializers.ValidationError('Invalid credentials, try again')
        
#         if not user.is_active:
#             raise serializers.ValidationError('Account disabled, contact admin')
            
#         if not user.is_verified:
#             raise serializers.ValidationError('Email is not verified')

#             # Check if user has the requested role
#         if role == 'restaurant' and not user.is_restaurant:
#             raise ValidationError({"error": "User is not authorized as restaurant"})
#         elif role == 'provider' and not user.is_provider:
#             raise ValidationError({"error": "User is not authorized as provider"})

#         # if not user.role:
#         #     raise serializers.ValidationError('Select a role for auth')
            
#         return {
#             'email': user.email,
#             'username': user.username,
#             'tokens': user.tokens,
#             # 'role':user.role
#         }

class LoginSerializer(serializers.Serializer):
    """
    Enhanced serializer for user authentication with role-based access control.
    Handles email/password validation and role verification.
    """
    email = serializers.EmailField(max_length=255, required=True, trim_whitespace=True)
    password = serializers.CharField(max_length=128, write_only=True, required=True, style={'input_type': 'password'})
    role = serializers.ChoiceField(choices=['restaurant', 'provider'], required=True)

    def validate_email(self, value):
        """Validate email format and normalize to lowercase."""
        return value.lower().strip()

    def validate(self, attrs):
        """Perform overall validation of the login data."""
        if not all([attrs.get('email'), attrs.get('password')]):
            raise serializers.ValidationError({"error": "Both email and password are required"})
        
        return attrs

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField(min_length=6, max_length=128, write_only=True)
    password_confirmation = serializers.CharField(min_length=6, max_length=128, write_only=True)
    
    def validate(self, attrs):
        password = attrs.get('password')
        password_confirmation = attrs.get('password_confirmation')
        token = attrs.get('token')
        
        if password != password_confirmation:
            raise serializers.ValidationError({'password': 'Passwords no coinciden'})
            
        # Validate token
        user = verify_password_reset_token(token)
        if not user:
            raise serializers.ValidationError({'token': 'Token invalido o experido'})
            
        attrs['user'] = user
        return attrs

class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(min_length=6, max_length=128, write_only=True)
    new_password = serializers.CharField(min_length=6, max_length=128, write_only=True)
    new_password_confirmation = serializers.CharField(min_length=6, max_length=128, write_only=True)
    
    def validate(self, attrs):
        current_password = attrs.get('current_password')
        new_password = attrs.get('new_password')
        new_password_confirmation = attrs.get('new_password_confirmation')
        
        if new_password != new_password_confirmation:
            raise serializers.ValidationError({'new_password': 'Las nuevas contraseñas deben coincidir'})
            
        return attrs