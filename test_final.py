#!/usr/bin/env python3
"""
Final test script for VAST Scanner
"""

import os
import sys
from app import create_app, db
from app.models import User

def test_everything():
    print("=" * 60)
    print("🔍 Testing VAST Scanner Setup")
    print("=" * 60)
    
    # Test 1: Check environment
    print("\n1. Checking environment variables...")
    db_url = os.environ.get('DATABASE_URL', 'Not set')
    print(f"   DATABASE_URL: {db_url}")
    
    # Test 2: Create app
    print("\n2. Creating Flask app...")
    app = create_app()
    print("   ✅ App created successfully")
    
    # Test 3: Test database
    print("\n3. Testing database connection...")
    with app.app_context():
        try:
            # Test connection
            db.session.execute('SELECT 1')
            print("   ✅ Database connection successful")
            
            # Create tables
            db.create_all()
            print("   ✅ Tables created/verified")
            
            # Check if user table exists
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            print(f"   📊 Tables: {', '.join(tables)}")
            
            # Test user creation
            print("\n4. Testing user operations...")
            test_user = User.query.filter_by(email='test@example.com').first()
            
            if not test_user:
                test_user = User(
                    username='test_user',
                    email='test@example.com',
                    is_verified=True,
                    is_2fa_enabled=False
                )
                test_user.set_password('Test@123')
                db.session.add(test_user)
                db.session.commit()
                print("   ✅ Test user created")
            else:
                print("   ✅ Test user already exists")
            
            # List users
            users = User.query.all()
            print(f"   👥 Total users: {len(users)}")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("🎉 Test complete!")
    print("=" * 60)

if __name__ == "__main__":
    test_everything()
