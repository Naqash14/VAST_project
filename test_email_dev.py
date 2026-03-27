#!/usr/bin/env python3
"""
Test email in development mode
"""

from flask import Flask
from flask_mail import Mail, Message
import os
from dotenv import load_dotenv

# Load .env
load_dotenv()

app = Flask(__name__)

# Configure from .env
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)

def test_email():
    print("=" * 60)
    print("📧 Testing Email Configuration")
    print("=" * 60)
    
    print(f"\nConfiguration:")
    print(f"  Server: {app.config['MAIL_SERVER']}")
    print(f"  Port: {app.config['MAIL_PORT']}")
    print(f"  Username: {app.config['MAIL_USERNAME']}")
    print(f"  Password: {'*' * 8 + app.config['MAIL_PASSWORD'][-4:] if app.config['MAIL_PASSWORD'] else 'Not set'}")
    
    test_email = input("\nEnter your email to send test OTP: ").strip()
    test_otp = "123456"
    
    with app.app_context():
        try:
            msg = Message(
                subject='VAST Scanner - Test Email',
                recipients=[test_email],
                html=f"<h2>Test OTP: {test_otp}</h2><p>If you receive this, email is working!</p>"
            )
            mail.send(msg)
            print(f"\n✅ Test email sent to {test_email}")
            print("   Check your inbox (and spam folder)")
        except Exception as e:
            print(f"\n❌ Failed: {e}")

if __name__ == "__main__":
    test_email()
