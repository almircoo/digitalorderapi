from django.test import TestCase

# Create your tests here.
class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    
    def post(self, request):
        """
        Handle login for different user roles (restaurant or provider).
        Returns customized response based on role.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Extract credentials and requested role
        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')
        role = serializer.validated_data.get('role')
        
        # Authenticate user
        user = authenticate(email=email, password=password)
        
        if not user:
            raise ValidationError({"error": "Invalid credentials"})
        
        # Check if user has the requested role
        if role == 'restaurant' and not user.is_restaurant:
            raise ValidationError({"error": "User is not authorized as restaurant"})
        elif role == 'provider' and not user.is_provider:
            raise ValidationError({"error": "User is not authorized as provider"})
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
        # Prepare response based on role
        response_data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'role': role,
            'user_id': user.id,
            'email': user.email,
        }
        
        # Add role-specific data to response
        if role == 'restaurant' and hasattr(user, 'restaurant'):
            response_data['restaurant_id'] = user.restaurant.id
            response_data['restaurant_name'] = user.restaurant.name
        elif role == 'provider' and hasattr(user, 'provider'):
            response_data['provider_id'] = user.provider.id
            response_data['provider_name'] = user.provider.name
        
        return Response(response_data, status=status.HTTP_200_OK)
