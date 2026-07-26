import os
import logging
import requests
import json

logger = logging.getLogger(__name__)

def send_otp_email(email, otp_code):
    """
    Send OTP email using Brevo REST API
    Works on Railway (no SMTP port blocking)
    """
    try:
        api_key = os.environ.get('BREVO_API_KEY')
        sender_email = os.environ.get('MAIL_DEFAULT_SENDER', 'vast.scanner@gmail.com')
        sender_name = os.environ.get('MAIL_SENDER_NAME', 'VAST Scanner')
        
        if not api_key:
            logger.error("❌ BREVO_API_KEY not set in environment")
            # Fallback: print OTP to console
            print(f"\n{'='*50}")
            print(f"📧 OTP for {email}: {otp_code}")
            print(f"(BREVO_API_KEY not configured)")
            print(f"{'='*50}\n")
            return True
        
        # Brevo API endpoint
        url = "https://api.brevo.com/v3/smtp/email"
        
        # Email content
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
        
        # Brevo API payload
        payload = {
            "sender": {
                "name": sender_name,
                "email": sender_email
            },
            "to": [
                {
                    "email": email,
                    "name": "User"
                }
            ],
            "subject": "VAST Scanner - Email Verification Code",
            "htmlContent": html_content
        }
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "api-key": api_key
        }
        
        # Send via Brevo API
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        
        if response.status_code in [200, 201, 202]:
            logger.info(f"✅ OTP email sent via Brevo API to {email}")
            print(f"\n✅ OTP email sent via Brevo API to {email}")
            return True
        else:
            logger.error(f"❌ Brevo API failed: {response.status_code} - {response.text}")
            # Fallback: print OTP
            print(f"\n{'='*50}")
            print(f"📧 OTP for {email}: {otp_code}")
            print(f"(Brevo API error: {response.status_code})")
            print(f"{'='*50}\n")
            return True
            
    except requests.exceptions.Timeout:
        logger.error(f"❌ Brevo API timeout for {email}")
        print(f"\n{'='*50}")
        print(f"📧 OTP for {email}: {otp_code}")
        print(f"(Brevo API timeout - use this code)")
        print(f"{'='*50}\n")
        return True
        
    except Exception as e:
        logger.error(f"❌ Email error: {str(e)}")
        print(f"\n{'='*50}")
        print(f"📧 OTP for {email}: {otp_code}")
        print(f"(Email error: {str(e)})")
        print(f"{'='*50}\n")
        return True
