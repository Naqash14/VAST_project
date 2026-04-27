#!/usr/bin/env python3
"""
Fix admin user creation
Run: python fix_admin.py
"""

from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    # Check if admin exists
    admin = User.query.filter_by(email='admin@vast.com').first()
    
    if admin:
        print(f"✅ Admin already exists: {admin.username}")
        # Ensure admin flag is set
        if not admin.is_admin:
            admin.is_admin = True
            db.session.commit()
            print("✅ Admin flag set")
    else:
        # Create admin user
        admin = User(
            username='admin',
            email='admin@vast.com',
            is_verified=True,
            is_admin=True
        )
        admin.set_password('Admin@123')
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin created: admin@vast.com / Admin@123")
    
    # List all admin users
    admins = User.query.filter_by(is_admin=True).all()
    print(f"\n📊 Admin users: {len(admins)}")
    for a in admins:
        print(f"   - {a.username} ({a.email})")

