#!/usr/bin/env python3
"""
Debug OTP and User Creation
"""

from app import create_app, db
from app.models import User, OTP
from pprint import pprint

app = create_app()

with app.app_context():
    print("="*60)
    print("🔍 DEBUG: Database Status")
    print("="*60)
    
    # Check all users
    users = User.query.all()
    print(f"\n👥 Users in database: {len(users)}")
    for user in users:
        print(f"   - ID: {user.id}, Username: {user.username}, Email: {user.email}, Verified: {user.is_verified}")
    
    # Check all OTPs
    otps = OTP.query.all()
    print(f"\n🔑 OTPs in database: {len(otps)}")
    for otp in otps:
        print(f"   - ID: {otp.id}, Email: {otp.email}, Code: {otp.otp_code}, Used: {otp.is_used}, Expires: {otp.expires_at}")
    
    # Check session (can't access directly here)
    print("\n⚠️  Note: Session data can only be checked in running app")
    
    print("\n" + "="*60)
