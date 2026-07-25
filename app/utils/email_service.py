from flask_mail import Message
from flask import current_app
from app import mail
import logging
from threading import Thread
import time

logger = logging.getLogger(__name__)

def send_async_email(app, msg):
    """Send email in background thread"""
    with app.app_context():
        try:
            time.sleep(1)  # Small delay for connection
            mail.send(msg)
            logger.info("✅ Email sent successfully")
        except Exception as e:
            logger.error(f"❌ Email failed: {str(e)}")

def send_otp_email(email, otp_code):
    """Send OTP email to user"""
    try:
        app = current_app._get_current_object()
        
        msg = Message(
            subject='VAST Scanner - Email Verification Code',
            recipients=[email],
            html=f'''
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{
                        font-family: 'Segoe UI', Arial, sans-serif;
                        background-color: #f5f7fa;
                        margin: 0;
                        padding: 0;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 20px auto;
                        background: white;
                        border-radius: 16px;
                        box-shadow: 0 8px 30px rgba(0,0,0,0.1);
                        overflow: hidden;
                    }}
                    .header {{
                        background: linear-gradient(135deg, #4361ee 0%, #3a0ca3 100%);
                        padding: 30px;
                        text-align: center;
                    }}
                    .header h1 {{
                        color: white;
                        margin: 0;
                        font-size: 28px;
                    }}
                    .content {{
                        padding: 40px 30px;
                    }}
                    .otp-box {{
                        background: #f0f4ff;
                        border: 2px dashed #4361ee;
                        border-radius: 12px;
                        padding: 25px;
                        text-align: center;
                        margin: 25px 0;
                    }}
                    .otp-code {{
                        font-size: 48px;
                        font-weight: 800;
                        letter-spacing: 10px;
                        color: #4361ee;
                        font-family: 'Courier New', monospace;
                    }}
                    .footer {{
                        background: #f8f9fa;
                        padding: 20px;
                        text-align: center;
                        color: #6c757d;
                        font-size: 14px;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 VAST Scanner</h1>
                        <p style="color: rgba(255,255,255,0.9);">Email Verification</p>
                    </div>
                    <div class="content">
                        <h2>Hello!</h2>
                        <p>Your verification code is:</p>
                        <div class="otp-box">
                            <div class="otp-code">{otp_code}</div>
                            <div style="color: #6c757d; margin-top: 10px;">Valid for 10 minutes</div>
                        </div>
                        <p>If you didn't request this, please ignore this email.</p>
                    </div>
                    <div class="footer">
                        <p>© 2026 VAST Scanner. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            '''
        )
        
        # Send in background thread
        thread = Thread(target=send_async_email, args=(app, msg))
        thread.daemon = True
        thread.start()
        
        logger.info(f"📧 OTP email queued for {email}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Email setup failed: {str(e)}")
        # Print OTP to console as fallback
        print(f"\n{'='*60}")
        print(f"📧 OTP for {email}: {otp_code}")
        print(f"(Email sending failed: {str(e)})")
        print(f"{'='*60}\n")
        return False
