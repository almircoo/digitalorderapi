# serializers.py
import re
from rest_framework import serializers
from .models import CustomUser, RestaurantProfile, ProviderProfile
from django.contrib.auth.password_validation import validate_password

RESTRICTED_USERNAMES = ["admin", "undefined", "null", "superuser", "root", "system"]

def sanitize_username(username):
    return re.sub(r'\W+', '', username)

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    profile_data = serializers.DictField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'first_name', 'last_name', 'user_type', 'password', 'profile_data']

    def validate_username(self, value):
        cleaned = sanitize_username(value)
        if cleaned.lower() in RESTRICTED_USERNAMES:
            raise serializers.ValidationError(f"The username '{cleaned}' is not allowed.")
        if ' ' in cleaned or not re.match(r'^[\w.@+-]+$', cleaned):
            raise serializers.ValidationError("Username contains invalid characters.")
        return cleaned

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already in use.")
        return value

    def validate(self, data):
        user_type = data.get('user_type')
        profile = data.get('profile_data', {})

        if user_type == 'restaurant':
            required = ['restaurant_name', 'restaurant_ruc', 'restaurant_address']
        elif user_type == 'provider':
            required = ['company_name', 'company_ruc', 'company_address']
        else:
            raise serializers.ValidationError("Invalid user type.")

        missing = [field for field in required if field not in profile or not profile[field]]
        if missing:
            raise serializers.ValidationError(f"Missing profile fields: {', '.join(missing)}")

        # Optional RUC format validation
        ruc_field = profile.get('restaurant_ruc') or profile.get('company_ruc')
        if not ruc_field or not ruc_field.isdigit() or len(ruc_field) != 11:
            raise serializers.ValidationError("RUC must be 11 digits.")

        return data

    def create(self, validated_data):
        profile_data = validated_data.pop('profile_data')
        password = validated_data.pop('password')
        user = CustomUser.objects.create_user(**validated_data, password=password)

        if user.user_type == 'restaurant':
            RestaurantProfile.objects.create(user=user, **profile_data)
        elif user.user_type == 'provider':
            ProviderProfile.objects.create(user=user, **profile_data)

        return user
