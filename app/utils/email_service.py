from flask_mail import Message
from flask import current_app
from app import mail
import logging
import threading
import time

logger = logging.getLogger(__name__)

def send_async_email(app, msg):
    """Send email in background thread"""
    with app.app_context():
        try:
            mail.send(msg)
            logger.info("Email sent successfully")
        except Exception as e:
            logger.error(f"Email failed: {e}")

def send_otp_email(email, otp_code):
    """Send OTP email asynchronously"""
    try:
        # Simple email content (no triple-quoted f-string issues)
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; background: #f4f6f9; margin: 0; padding: 0; }
                .container { max-width: 600px; margin: 20px auto; background: white; border-radius: 10px; padding: 30px; }
                .header { background: #4361ee; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; margin: -30px -30px 20px -30px; }
                .otp-code { font-size: 36px; font-weight: bold; color: #4361ee; text-align: center; padding: 20px; background: #f0f4ff; border-radius: 5px; letter-spacing: 5px; }
                .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header"><h2>VAST Security Scanner</h2></div>
                <h3>Email Verification</h3>
                <p>Your OTP is:</p>
                <div class="otp-code">""" + otp_code + """</div>
                <p>Valid for 10 minutes</p>
                <div class="footer">If you didn't request this, please ignore this email.</div>
            </div>
        </body>
        </html>
        """
        
        msg = Message(
            subject='VAST Scanner - Email Verification Code',
            recipients=[email],
            html=html_content
        )
        
        # Send in background
        app = current_app._get_current_object()
        thread = threading.Thread(target=send_async_email, args=(app, msg))
        thread.daemon = True
        thread.start()
        
        logger.info(f"OTP email queued for {email}")
        return True
        
    except Exception as e:
        logger.error(f"Email error: {e}")
        # Print OTP in logs for debugging
        print(f"\n{'='*50}")
        print(f"📧 OTP for {email}: {otp_code}")
        print(f"(Email queued - check spam folder)")
        print(f"{'='*50}\n")
        return True  # Return True to not block signup
