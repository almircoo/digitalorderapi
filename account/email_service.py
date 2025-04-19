import os
import jwt
from datetime import datetime, timedelta
import resend
from django.conf import settings
from django.urls import reverse

class ResendEmailService:
    def __init__(self):
        # Configuracion de Resend API
        api_key = settings.RESEND_API_KEY
        if not api_key:
            raise ValueError("RESEND_API_KEY is not configured in settings")
        resend.api_key = api_key
        
    def generate_verification_token(self, user):
        """Generate a verification token for email """
        payload = {
            'email': user.email,
            'exp': datetime.utcnow() + timedelta(hours=24),
            'iat': datetime.utcnow(),
            'type': 'email_verification',
            'user_id': str(user.id)
        }
        
        token = jwt.encode(
            payload,
            settings.SECRET_KEY,
            algorithm='HS256'
        )
        
        return token
    
    def send_verification_email(self, user, request):
        """Send verification email using Resend API"""
        verification_token = self.generate_verification_token(user)
        
        # Verificaion de  URL y dominio
        domain = request.get_host()
        protocol = 'https' if request.is_secure() else 'http'
        verification_url = f"{protocol}://{domain}/auth/verify-email/{verification_token}/"
        
        # contenido del email
        subject = "Verifique su correo"
        
        if hasattr(user, 'role') and user.role == 'restaurant':
            greeting = f"Hola {user.first_name}, Restaurant Manager"
        else:
            greeting = f"Hola {user.first_name}, Proveedor CEO"
        
        html_content = f"""
            <html>
            <body>
                <h2>{greeting}</h2>
                <p>¡Gracias por registrarte! Por favor, verifica tu correo electrónico haciendo clic en el siguiente enlace:</p>
                <p><a href="{verification_url}">verificar mi cuenta</a></p>
                <p>Este enlace es válido por 24 horas.</p>
                <p>Si no se ha registrado para obtener una cuenta, ignore este correo electrónico.</p>
                <p><strong>Team DigitalOrder </strong></p>
            </body>
            </html>
        """
        
        try:
            params = {
                "from": "DigitalOrder <team@digitalorder.lat>",
                "to": user.email,
                "subject": subject,
                "html": html_content,
            }
            
            # envia el mensahe al restaurant o al provedor
            response = resend.Emails.send(params)
            return True, response.get("id")

        except Exception as e:
            return False, str(e)