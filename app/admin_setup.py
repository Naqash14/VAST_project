"""
Admin user setup - ensures admin exists
"""

from app import db
from app.models import User

def ensure_admin_exists():
    """Ensure admin user exists in database"""
    with db.session.begin_nested():
        admin = User.query.filter_by(email='admin@vast.com').first()
        
        if not admin:
            admin = User(
                username='admin',
                email='admin@vast.com',
                is_verified=True,
                is_admin=True
            )
            admin.set_password('Admin@123')
            db.session.add(admin)
            print("✅ Admin user created: admin@vast.com / Admin@123")
        else:
            # Ensure admin flag is set
            if not admin.is_admin:
                admin.is_admin = True
                print("✅ Admin flag set for existing admin")
    
    db.session.commit()
