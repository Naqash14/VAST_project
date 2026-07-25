from flask_mail import Message
from flask import current_app
from app import mail
import logging

logger = logging.getLogger(__name__)

def send_otp_email(email, otp_code):
    """
    Send OTP email to user
    """
    try:
        msg = Message(
            subject='VAST Scanner - Email Verification Code',
            recipients=[email],
            html=f'''
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; background: #f5f7fa; }}
                    .container {{ max-width: 600px; margin: 20px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .header {{ background: #4361ee; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; margin: -30px -30px 20px -30px; }}
                    .otp {{ font-size: 36px; font-weight: bold; color: #4361ee; text-align: center; padding: 20px; background: #f0f4ff; border-radius: 5px; letter-spacing: 5px; }}
                    .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header"><h2>VAST Scanner</h2></div>
                    <h3>Email Verification</h3>
                    <p>Your verification code is:</p>
                    <div class="otp">{otp_code}</div>
                    <p>Valid for 10 minutes.</p>
                    <div class="footer"><p>If you didn't request this, ignore this email.</p></div>
                </div>
            </body>
            </html>
            '''
        )
        
        mail.send(msg)
        logger.info(f"OTP email sent to {email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        print(f"\n📧 OTP for {email}: {otp_code}\n")
        return False
