"""
Admin Auto-Creation Module
Ensures admin user exists based on .env credentials
"""

import os
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)
load_dotenv()


def ensure_admin_exists():
    """
    Check if admin exists in database.
    If not, create from .env credentials.
    If yes, do nothing.
    
    Note: This function must be called within an app context
    """
    try:
        # Import db and models INSIDE the function to avoid circular imports
        from app import db
        from app.models import User
        
        # Get admin credentials from environment
        admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@vast.local')
        admin_password = os.environ.get('ADMIN_PASSWORD')
        
        # Check if credentials exist
        if not admin_password:
            print("⚠️ ADMIN_PASSWORD not set in .env - skipping admin creation")
            print("   Add ADMIN_PASSWORD=your-secure-password to .env")
            return
        
        # Check if admin already exists
        existing_admin = User.query.filter_by(username=admin_username).first()
        
        if existing_admin:
            if existing_admin.is_admin:
                print(f"✅ Admin user '{admin_username}' already exists")
            else:
                # Upgrade to admin if exists but not admin
                existing_admin.is_admin = True
                existing_admin.is_verified = True
                db.session.commit()
                print(f"✅ User '{admin_username}' upgraded to admin")
            return
        
        # Create new admin user
        admin_user = User(
            username=admin_username,
            email=admin_email,
            is_verified=True,
            is_admin=True,
            is_2fa_enabled=False
        )
        admin_user.set_password(admin_password)
        
        db.session.add(admin_user)
        db.session.commit()
        
        print(f"✅ Admin user '{admin_username}' created from .env")
        print(f"   Email: {admin_email}")
        print(f"   Password: {admin_password}")
        print("   ⚠️ Please change password after first login!")
        
    except Exception as e:
        print(f"❌ Admin creation failed: {str(e)}")
        logger.error(f"Admin creation error: {e}")
        try:
            from app import db
            db.session.rollback()
        except:
            pass


def get_admin_info():
    """
    Get admin info without exposing password
    Returns: dict or None
    """
    try:
        from app import db
        from app.models import User
        
        admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
        admin_user = User.query.filter_by(username=admin_username, is_admin=True).first()
        
        if admin_user:
            return {
                'username': admin_user.username,
                'email': admin_user.email,
                'is_admin': admin_user.is_admin,
                'created_at': admin_user.created_at
            }
        return None
    except Exception as e:
        print(f"❌ Error fetching admin info: {e}")
        return None
