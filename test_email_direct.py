#!/usr/bin/env python3
import smtplib
from email.mime.text import MIMEText

# APNI EMAIL AUR PASSWORD YAHAN DALO
GMAIL_USER = "batoolkhadija894@gmail.com"  # Apna email
GMAIL_APP_PASSWORD = "your-16-digit-app-password"  # App password
TO_EMAIL = "batoolkhadija894@gmail.com"  # Jis email par test bhejna hai

print("="*50)
print("TESTING EMAIL DIRECTLY")
print("="*50)

try:
    # Create message
    msg = MIMEText("This is a test email from VAST Scanner")
    msg['Subject'] = "Test Email from VAST"
    msg['From'] = GMAIL_USER
    msg['To'] = TO_EMAIL
    
    # Connect to Gmail
    print("Connecting to Gmail SMTP...")
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    
    print(f"Logging in as {GMAIL_USER}...")
    server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
    
    print(f"Sending email to {TO_EMAIL}...")
    server.send_message(msg)
    server.quit()
    
    print("✅ SUCCESS! Email sent!")
    print(f"Check {TO_EMAIL} inbox (and spam folder)")
    
except smtplib.SMTPAuthenticationError as e:
    print("❌ AUTHENTICATION FAILED")
    print("\nSOLUTION:")
    print("1. Go to: https://myaccount.google.com/security")
    print("2. Enable '2-Step Verification'")
    print("3. Go to: https://myaccount.google.com/apppasswords")
    print("4. Generate App Password for 'Mail'")
    print("5. Use that 16-digit password (NOT your regular password)")
    
except Exception as e:
    print(f"❌ ERROR: {e}")
