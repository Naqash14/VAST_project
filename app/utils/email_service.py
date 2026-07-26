from flask_mail import Message
from flask import current_app
from app import mail
import logging
import threading
import time
import os
import requests

logger = logging.getLogger(__name__)

def send_async_email(app, msg):
    """Send email in background thread (SMTP)"""
    with app.app_context():
        try:
            mail.send(msg)
            logger.info("Email sent successfully via SMTP")
        except Exception as e:
            logger.error(f"SMTP email failed: {e}")

def send_otp_email(email, otp_code):
    """
    Send OTP email using Brevo SMTP
    Falls back to console logging if SMTP fails
    """
    try:
        # Create email content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f6f9; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); overflow: hidden; }}
                .header {{ background: linear-gradient(135deg, #4361ee 0%, #3a0ca3 100%); padding: 30px; text-align: center; }}
                .header h1 {{ color: white; margin: 0; font-size: 28px; font-weight: 600; }}
                .header p {{ color: rgba(255,255,255,0.9); margin: 5px 0 0; }}
                .content {{ padding: 30px; }}
                .otp-box {{ background: #f0f4ff; border: 2px dashed #4361ee; border-radius: 12px; padding: 25px; text-align: center; margin: 25px 0; }}
                .otp-code {{ font-size: 48px; font-weight: 800; letter-spacing: 10px; color: #4361ee; font-family: 'Courier New', monospace; }}
                .info {{ background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #6c757d; font-size: 14px; border-top: 1px solid #dee2e6; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 VAST Security Scanner</h1>
                    <p>Email Verification</p>
                </div>
                
                <div class="content">
                    <h2>Hello!</h2>
                    <p>Thank you for registering with <strong>VAST Scanner</strong>. Please use the OTP below to verify your email address.</p>
                    
                    <div class="otp-box">
                        <div style="color: #6c757d; margin-bottom: 15px; font-size: 14px;">Your verification code is:</div>
                        <div class="otp-code">{otp_code}</div>
                        <div style="margin-top: 20px; color: #6c757d; font-size: 14px;">Valid for <strong>10 minutes</strong></div>
                    </div>
                    
                    <div class="info">
                        <strong>📱 How to use:</strong><br>
                        1. Enter this 6-digit code in the verification page<br>
                        2. Complete your registration<br>
                        3. You'll be redirected to login
                    </div>
                    
                    <p style="text-align: center; color: #6c757d; font-size: 14px; margin-top: 25px;">
                        If you didn't request this, please ignore this email.
                    </p>
                </div>
                
                <div class="footer">
                    <p>© 2026 VAST Vulnerability Scanner. All rights reserved.</p>
                    <p style="font-size: 12px; color: #adb5bd;">This is an automated message, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg = Message(
            subject='VAST Scanner - Email Verification Code',
            recipients=[email],
            html=html_content,
            sender=os.environ.get('MAIL_DEFAULT_SENDER', 'vast.scanner@gmail.com')
        )
        
        # Send via SMTP
        app = current_app._get_current_object()
        thread = threading.Thread(target=send_async_email, args=(app, msg))
        thread.daemon = True
        thread.start()
        
        logger.info(f"✅ OTP email queued for {email}")
        print(f"\n📧 OTP queued for {email}: {otp_code}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Email send failed: {str(e)}")
        # Print OTP in logs for debugging
        print(f"\n{'='*50}")
        print(f"📧 OTP for {email}: {otp_code}")
        print(f"(Email failed - use this code to verify)")
        print(f"{'='*50}\n")
        return True  # Return True to not block signup
