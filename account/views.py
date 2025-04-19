from django.shortcuts import render, redirect
from rest_framework import generics, status, views, permissions
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from .serializers import (RegisterSerializer, LoginSerializer, RestaurantProfileSerializer, ProviderProfileSerializer,
                        PasswordResetRequestSerializer, PasswordResetConfirmSerializer, ChangePasswordSerializer)
from .models import CustomUser, RestaurantProfile, ProviderProfile
from .utils import verify_email_token 
from django.conf import settings
from django.db import transaction
from .email_service import ResendEmailService
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import ValidationError

import logging

logger = logging.getLogger(__name__)


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    
    @transaction.atomic # asegura la integridad d elos datos
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Create the appropriate profile based on the user's role
            if user.role == 'restaurant':
                restaurant_data = request.data.get('restaurant_profile', {})
                restaurant_serializer = RestaurantProfileSerializer(data=restaurant_data)
                if restaurant_serializer.is_valid():
                    restaurant_serializer.save(user=user)
                else:
                    # If restaurant profile data is invalid, delete the user and return errors
                    user.delete()
                    return Response(restaurant_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                    
            elif user.role == 'provider':
                provider_data = request.data.get('provider_profile', {})
                provider_serializer = ProviderProfileSerializer(data=provider_data)
                if provider_serializer.is_valid():
                    provider_serializer.save(user=user)
                else:
                    # If provider profile data is invalid, delete the user and return errors
                    user.delete()
                    return Response(provider_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            # # Send verification email
            try:
                email_service = ResendEmailService()
                success, result = email_service.send_verification_email(user, request)
                
                if not success:
                    # Optionally log the error
                    print(f"Error sending verification email: {result}")
            except Exception as e:
                # Log the error but don't fail registration
                print(f"Failed to send verification email: {str(e)}")
            
            return Response({
                'user': serializer.data,
                'message': 'User registered successfully. Please check your email to verify your account.'
            }, status=status.HTTP_201_CREATED)
            # return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class LoginAPIView(generics.GenericAPIView):
#     serializer_class = LoginSerializer
    
#     # def post(self, request):
#     #     serializer = self.serializer_class(data=request.data)
#     #     serializer.is_valid(raise_exception=True)
        
#     #     return Response(serializer.data, status=status.HTTP_200_OK)
    
#     def post(self, request):
#         """
#         Handle login for different user roles (restaurant or provider).
#         Returns customized response based on role.
#         """
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
        
#         # Extract credentials and requested role
#         email = serializer.validated_data.get('email')
#         password = serializer.validated_data.get('password')
#         role = serializer.validated_data.get('role')
        
#         # Authenticate user
#         user = auth.authenticate(email=email, password=password)
#         # user.is_valid(raise_exception=True)
#         # print(user)
        
#         # if not user:
#         #     raise ValidationError({"error": "Invalid credentials"})
        
        
        
#         # Generate tokens
#         refresh = RefreshToken.for_user(user)
        
#         # Prepare response based on role
#         response_data = {
#             'refresh': str(refresh),
#             'access': str(refresh.access_token),
#             'role': role,
#             'user_id': user.id,
#             'email': user.email,
#         }
        
#         # Add role-specific data to response
#         if role == 'restaurant' and hasattr(user, 'restaurant'):
#             response_data['restaurant_id'] = user.restaurant.id
#             response_data['restaurant_name'] = user.restaurant.name
#         elif role == 'provider' and hasattr(user, 'provider'):
#             response_data['provider_id'] = user.provider.id
#             response_data['provider_name'] = user.provider.name
        
#         return Response(response_data, status=status.HTTP_200_OK)

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    
    def post(self, request):
        """
        Enhanced login endpoint for role-based authentication.
        Provides role-specific responses and detailed error messages.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Extract credentials and requested role
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        role = serializer.validated_data['role']
        
        # Log authentication attempt (without password)
        logger.info(f"Authentication attempt for email: {email}, role: {role}")
        
        # Authenticate user
        user = authenticate(email=email, password=password)
        
        if not user:
            logger.warning(f"Failed authentication attempt for email: {email}")
            return Response(
                {"error": "Invalid credentials"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        # Check if user account is active
        if not user.is_active:
            logger.warning(f"Inactive user attempted login: {email}")
            return Response(
                {"error": "Account is inactive or suspended"}, 
                status=status.HTTP_403_FORBIDDEN
            )
            
        # Verify role authorization
        if role == 'restaurant' and not user.role:
            logger.warning(f"User {email} attempted unauthorized restaurant access")
            return Response(
                {"error": "User is not authorized as restaurant"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        elif role == 'provider' and not user.role:
            logger.warning(f"User {email} attempted unauthorized provider access")
            return Response(
                {"error": "User is not authorized as provider"}, 
                status=status.HTTP_403_FORBIDDEN
            )
            
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        
        # Build response based on role
        response_data = self._build_role_specific_response(user, role, refresh, access_token)
        
        logger.info(f"Successful login for user: {email}, role: {role}")
        return Response(response_data, status=status.HTTP_200_OK)
    
    def _build_role_specific_response(self, user, role, refresh, access_token):
        """Helper method to build role-specific response data."""
        response_data = {
            'refresh': str(refresh),
            'access': access_token,
            'role': role,
            'user_id': user.id,
            'email': user.email,
        }
        
        # Add role-specific data
        try:
            if role == 'restaurant' and hasattr(user, 'restaurant'):
                restaurant = user.restaurant
                response_data.update({
                    'restaurant_id': restaurant.id,
                    'restaurant_name': restaurant.name,
                    # Add any other relevant restaurant fields
                })
            elif role == 'provider' and hasattr(user, 'provider'):
                provider = user.provider
                response_data.update({
                    'provider_id': provider.id,
                    'provider_name': provider.name,
                    # Add any other relevant provider fields
                })
        except Exception as e:
            # Log the error but don't expose details to client
            logger.error(f"Error retrieving role data: {str(e)}")
            
        return response_data


class UserProfileView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        data = {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role
        }
        
        # Agregar datos a 2 perfiles
        if user.role == 'restaurant':
            try:
                restaurant_profile = RestaurantProfile.objects.get(user=user)
                restaurant_data = RestaurantProfileSerializer(restaurant_profile).data
                data['restaurant_panel'] = restaurant_data
            except RestaurantProfile.DoesNotExist:
                data['restaurant_panel'] = None
                
        elif user.role == 'provider':
            try:
                provider_profile = ProviderProfile.objects.get(user=user)
                provider_data = ProviderProfileSerializer(provider_profile).data
                data['provider_panel'] = provider_data
            except ProviderProfile.DoesNotExist:
                data['provider_panel'] = None

        return Response(data, status=status.HTTP_200_OK)
        

class VerifyEmailView(APIView):
    def get(self, request, token):

        user = verify_email_token(token)
        
        if user is None:
            return Response({'error': 'Token invalio o expirado'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not user.is_verified:
            user.is_verified = True
            user.is_active = True
            user.save()
            
            # Redirect to frontend success page
            frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
            return redirect(f"{frontend_url}/email-verification-success") #pendiente validar en reactjs
        
        # Already verified, redirect to login
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
        return redirect(f"{frontend_url}/login")

class ResendVerificationEmailView(APIView):
    def post(self, request):
        email = request.data.get('email', '')
        
        try:
            user = CustomUser.objects.get(email=email)
            
            if user.is_verified:
                return Response({'message': 'Email ya verificado'}, status=status.HTTP_400_BAD_REQUEST)
                
            success, result = send_verification_email(user, request)
            
            if success:
                return Response({'message': 'Emaul de verificación enviado exitosamente'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': f'Failed to send email: {result}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except CustomUser.DoesNotExist:
            return Response({'message': 'Sse ha enviado un email de verificación.'}, status=status.HTTP_200_OK)


class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        
        try:
            user = CustomUser.objects.get(email=email)
            success, result = send_password_reset_email(user, request)
            
            if not success:
                # Log the error but don't expose it to the user
                print(f"Failed to send password reset email: {result}")
        except CustomUser.DoesNotExist:
            # Don't reveal whether a user exists or not for security
            pass
        
        # Always return success to prevent email enumeration attacks
        return Response({
            'message': 'SE ha enviado un enlace para restablecer la contraseña.'
        }, status=status.HTTP_200_OK)

class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data['user']
        password = serializer.validated_data['password']
        
        # Set new password
        user.set_password(password)
        user.save()
        
        return Response({
            'message': 'Password has been reset successfully.'
        }, status=status.HTTP_200_OK)

class ChangePasswordView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        current_password = serializer.validated_data['current_password']
        new_password = serializer.validated_data['new_password']
        
        # Check if current password is correct
        if not user.check_password(current_password):
            return Response({
                'error': 'Current password is incorrect.'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Set new password
        user.set_password(new_password)
        user.save()
        
        return Response({
            'message': 'Password changed successfully.'
        }, status=status.HTTP_200_OK)

