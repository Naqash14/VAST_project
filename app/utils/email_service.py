from flask_mail import Message
from flask import current_app
from app import mail
import logging
import os

logger = logging.getLogger(__name__)

def send_otp_email(email, otp_code):
    """Send OTP email - Works on Railway with SMTP relay"""
    try:
        # Check if we're on Railway
        is_railway = os.environ.get('RAILWAY_ENVIRONMENT') == 'production'
        
        # Railway uses port 25 for SMTP, Gmail uses 587
        if is_railway:
            # Use Railway's SMTP relay (port 25)
            current_app.config['MAIL_PORT'] = 25
            current_app.config['MAIL_USE_TLS'] = False
            current_app.config['MAIL_USE_SSL'] = False
        
        msg = Message(
            subject='VAST Scanner - Email Verification Code',
            recipients=[email],
            html=f'''
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; background: #f4f6f9; padding: 20px; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .header {{ background: #4361ee; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; margin: -30px -30px 20px -30px; }}
                    .otp-box {{ background: #f0f4ff; border: 2px dashed #4361ee; padding: 20px; text-align: center; font-size: 36px; font-weight: bold; letter-spacing: 5px; color: #4361ee; border-radius: 8px; margin: 20px 0; }}
                    .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header"><h2>VAST Security Scanner</h2></div>
                    <h3>Email Verification</h3>
                    <p>Your verification code is:</p>
                    <div class="otp-box">{otp_code}</div>
                    <p>This code will expire in <strong>10 minutes</strong>.</p>
                    <div class="footer"><p>If you didn't request this, please ignore this email.</p></div>
                </div>
            </body>
            </html>
            '''
        )
        
        # Try to send with timeout
        mail.send(msg)
        logger.info(f"✅ OTP email sent to {email}")
        return True
        
    except Exception as e:
        logger.error(f"Email failed: {e}")
        # Fallback: Print OTP to logs (visible in Railway logs)
        print(f"\n{'='*50}")
        print(f"📧 OTP for {email}: {otp_code}")
        print(f"(Email sending failed - use this OTP from logs)")
        print(f"{'='*50}\n")
        return False
