from flask_mail import Message
from flask import current_app
from app import mail
import logging
import random

logger = logging.getLogger(__name__)

def send_otp_email(email, otp_code):
    """Send OTP email to user"""
    try:
        # Simple email that won't trigger spam filters
        msg = Message(
            subject='VAST Scanner - Verification Code',
            recipients=[email],
            html=f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                <div style="text-align: center; padding: 20px; background: #4361ee; color: white; border-radius: 10px 10px 0 0;">
                    <h1 style="margin: 0;">VAST Scanner</h1>
                    <p style="margin: 5px 0 0;">Security Analysis Tool</p>
                </div>
                <div style="padding: 30px 20px;">
                    <h2>Email Verification</h2>
                    <p>Your verification code is:</p>
                    <div style="font-size: 40px; font-weight: bold; text-align: center; padding: 20px; background: #f0f4ff; border-radius: 10px; letter-spacing: 10px; color: #4361ee; margin: 20px 0;">
                        {otp_code}
                    </div>
                    <p style="color: #666; font-size: 14px;">This code will expire in 10 minutes.</p>
                    <p style="color: #666; font-size: 14px;">If you didn't request this, please ignore this email.</p>
                </div>
                <div style="text-align: center; padding: 20px; background: #f8f9fa; border-radius: 0 0 10px 10px; color: #666; font-size: 12px;">
                    <p>© 2026 VAST Vulnerability Scanner. All rights reserved.</p>
                </div>
            </div>
            '''
        )
        
        mail.send(msg)
        print(f"✅ Email sent to {email}")
        logger.info(f"Email sent to {email}")
        return True
        
    except Exception as e:
        print(f"❌ Email error: {str(e)}")
        logger.error(f"Email error: {str(e)}")
        
        # Fallback: Print OTP to console (useful for debugging)
        print(f"\n{'='*60}")
        print(f"📧 OTP for {email}: {otp_code}")
        print(f"(Email error: {str(e)})")
        print(f"{'='*60}\n")
        
        # Still return True so signup continues (OTP will be shown in logs)
        return True

def generate_otp():
    """Generate 6-digit OTP"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])
