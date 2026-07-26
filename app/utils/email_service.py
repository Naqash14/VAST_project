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
    with app.app_context():
        try:
            mail.send(msg)
            logger.info("Email sent successfully")
        except Exception as e:
            logger.error(f"Email failed: {e}")

def send_otp_email(email, otp_code):
    """Send OTP email using Resend email service"""
    try:
        api_key = os.environ.get('RESEND_API_KEY')
        sender_email = os.environ.get('SENDER_EMAIL', 'onboarding@resend.dev')
        
        if not api_key:
            logger.error("❌ RESEND_API_KEY not set")
            return _send_otp_email_smtp(email, otp_code)
        
        # Send via Resend API
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": sender_email,
                "to": email,
                "subject": "Your VAST Scanner OTP - Email Verification",
                "html": f'''
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
                '''
            }
        )
        
        if response.status_code == 200:
            logger.info(f"✅ OTP email sent via Resend to {email}")
            print(f"\n✅ OTP sent to {email}")
            return True
        else:
            logger.error(f"❌ Resend failed ({response.status_code}): {response.text}")
            return _send_otp_email_smtp(email, otp_code)
            
    except Exception as e:
        logger.error(f"❌ Resend error: {e}")
        return _send_otp_email_smtp(email, otp_code)


def _send_otp_email_smtp(email, otp_code):
    """Fallback: Send OTP email using SMTP"""
    try:
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f4f6f9; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; margin: 20px auto; background: white; border-radius: 10px; padding: 30px; }}
                .header {{ background: #4361ee; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; margin: -30px -30px 20px -30px; }}
                .otp-code {{ font-size: 36px; font-weight: bold; color: #4361ee; text-align: center; padding: 20px; background: #f0f4ff; border-radius: 5px; letter-spacing: 5px; }}
                .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header"><h2>VAST Security Scanner</h2></div>
                <h3>Email Verification</h3>
                <p>Your OTP is:</p>
                <div class="otp-code">{otp_code}</div>
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
        
        app = current_app._get_current_object()
        thread = threading.Thread(target=send_async_email, args=(app, msg))
        thread.daemon = True
        thread.start()
        
        logger.info(f"OTP queued via SMTP for {email}")
        print(f"\n📧 OTP queued for {email}: {otp_code}")
        return True
        
    except Exception as e:
        logger.error(f"SMTP error: {e}")
        print(f"\n{'='*50}")
        print(f"📧 OTP for {email}: {otp_code}")
        print(f"{'='*50}\n")
        return True
