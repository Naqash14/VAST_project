from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    # Check if admin exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@vast.local',
            is_verified=True,
            is_admin=True
        )
        admin.set_password('Admin@123')
        db.session.add(admin)
        db.session.commit()
        print('✅ Admin user created: admin / Admin@123')
    else:
        # Ensure admin flag is set
        admin.is_admin = True
        db.session.commit()
        print('✅ Admin user already exists')
