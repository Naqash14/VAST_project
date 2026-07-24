import threading
from flask_mail import Message
from app import mail
import logging

logger = logging.getLogger(__name__)

def send_async_email(app, msg):
    """Send email in background thread"""
    with app.app_context():
        try:
            mail.send(msg)
            logger.info("Email sent successfully")
        except Exception as e:
            logger.error(f"Email failed: {e}")

def send_otp_email(email, otp_code, purpose='signup', username=None):
    """Send OTP email without blocking"""
    try:
        from flask import current_app
        
        html = f"""
        <div style="font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; background: #f4f6f9;">
            <div style="background: #4361ee; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                <h2>🔐 VAST Security Scanner</h2>
            </div>
            <div style="background: white; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
                <h3>Email Verification</h3>
                <p>Your verification code is:</p>
                <div style="font-size: 36px; font-weight: bold; color: #4361ee; text-align: center; padding: 20px; background: #f0f4ff; border-radius: 8px; letter-spacing: 5px;">
                    {otp_code}
                </div>
                <p style="color: #666; font-size: 14px; margin-top: 20px;">Valid for 10 minutes</p>
            </div>
        </div>
        """
        
        msg = Message(
            subject='VAST Scanner - Email Verification',
            recipients=[email],
            html=html
        )
        
        # Send in background
        from flask import current_app
        thread = threading.Thread(target=send_async_email, args=(current_app._get_current_object(), msg))
        thread.daemon = True
        thread.start()
        
        logger.info(f"OTP email queued for {email}")
        return True
        
    except Exception as e:
        logger.error(f"Email error: {e}")
        return False
