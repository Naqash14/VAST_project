from flask_mail import Message
from flask import current_app
from app import mail
import logging

logger = logging.getLogger(__name__)

def send_otp_email(email, otp_code):
    """
    Send OTP email - Development mode with Gmail
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
                    body {{
                        font-family: Arial, sans-serif;
                        background-color: #f4f6f9;
                        margin: 0;
                        padding: 0;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 20px auto;
                        background: white;
                        border-radius: 10px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }}
                    .header {{
                        background: #4361ee;
                        color: white;
                        padding: 20px;
                        text-align: center;
                        border-radius: 10px 10px 0 0;
                    }}
                    .content {{
                        padding: 30px;
                    }}
                    .otp-box {{
                        background: #f0f4ff;
                        border: 2px dashed #4361ee;
                        padding: 20px;
                        text-align: center;
                        font-size: 36px;
                        font-weight: bold;
                        letter-spacing: 5px;
                        color: #4361ee;
                        border-radius: 8px;
                        margin: 20px 0;
                    }}
                    .footer {{
                        text-align: center;
                        padding: 20px;
                        color: #666;
                        font-size: 12px;
                        border-top: 1px solid #eee;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>VAST Security Scanner</h2>
                    </div>
                    <div class="content">
                        <h3>Email Verification</h3>
                        <p>Hello,</p>
                        <p>Thank you for registering with VAST Scanner. Please use the following OTP to verify your email:</p>
                        
                        <div class="otp-box">
                            {otp_code}
                        </div>
                        
                        <p>This code will expire in <strong>10 minutes</strong>.</p>
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
        
        # Send email
        mail.send(msg)
        print(f"\n✅ Email sent successfully to {email}")
        logger.info(f"OTP email sent to {email}")
        return True
        
    except Exception as e:
        print(f"\n❌ Email sending failed: {str(e)}")
        logger.error(f"Failed to send email to {email}: {str(e)}")
        return False
