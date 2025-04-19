import os
import jwt
from datetime import datetime, timedelta
from django.conf import settings
import resend
from django.urls import reverse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

# verify emaul token
def verify_email_token(token):
    """Verify email token"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        
        # Comprueba si el token es para verificacinn de email
        if payload.get('type') != 'email_verification':
            return None
            
        # obtiene el usuario por email
        from .models import CustomUser
        user = CustomUser.objects.get(email=payload['email'])
        return user
    except jwt.ExpiredSignatureError:
        return Response(
            {'error': 'El enlace de verificación ha expirado'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    except jwt.InvalidTokenError:
        return Response(
            {'error': 'Token de verificación no válido'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception:
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# generate reset password tocken
def generate_password_reset_token(user):
    """Generate a password reset token"""
    payload = {
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(hours=1),  # el token expira en 1 hora
        'iat': datetime.utcnow(),
        'type': 'password_reset'
    }
    
    token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm='HS256'
    )
    
    return token

# send mail for reset password
def send_password_reset_email(user, request):
    """ envia emil con Resend API"""
    reset_token = generate_password_reset_token(user)
    current_site = request.get_host()
    reset_url = f"http://{current_site}/reset-password/{reset_token}/"
    
    # Constructura del mail a enviar
    subject = "Cambiar tu contraseña"
    
    html_content = f"""
        <html>
        <body>
            <h2>Hola {user.first_name},</h2>
            <p>Recibimos una solicitud para restablecer su contraseña. Haga clic en el enlace a continuación para establecer una nueva contraseña:</p>
            <p><a href="{reset_url}">Restablecer mi contraseña</a></p>
            <p>Este enlace es válido por 1 hora.</p>
            <p>Si no solicitó este restablecimiento de contraseña, ignore este correo electrónico o comuníquese con el soporte tecnico</p>
            <p><strong>DigitalOrder Team</strong></p>
        </body>
        </html>
    """
    
    try:
        params = {
            "from": "DigitalOrder<team@digitalorder.lat>",
            "to": user.email,
            "subject": subject,
            "html": html_content,
        }
        
        email = resend.Emails.send(params)
        return True, email["id"]
    except Exception as e:
        return False, str(e)

def verify_password_reset_token(token):
    """Verifica el token de cambio de contraseña"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        
        # Comprobar si el token es para cambiar la contraseña
        if payload.get('type') != 'password_reset':
            return None
            
        # obtner usario por email
        from .models import CustomUser
        user = CustomUser.objects.get(email=payload['email'])
        return user
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        return None


