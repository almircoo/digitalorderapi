from django.urls import path
from .views import ( RegisterView, LoginAPIView, UserProfileView, 
    VerifyEmailView, ResendVerificationEmailView,
    PasswordResetRequestView, PasswordResetConfirmView, ChangePasswordView
)
urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-verification-email/', ResendVerificationEmailView.as_view(), name='resend-verification-email'),
    path('profile/', UserProfileView.as_view(), name='profile'),

    path('password-reset-request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
]