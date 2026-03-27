#!/usr/bin/env python3
from app import create_app, login_manager
from app.models import User

app = create_app()

with app.app_context():
    print("="*50)
    print("CHECKING LOGIN MANAGER")
    print("="*50)
    
    # Check if login_manager exists
    print(f"Login Manager: {login_manager}")
    print(f"Login View: {login_manager.login_view}")
    
    # Check if user_loader is registered
    try:
        user = User.query.first()
        if user:
            loaded = login_manager._load_user()
            print(f"✓ User loader working")
        else:
            print("! No users in database yet")
    except Exception as e:
        print(f"✗ User loader error: {e}")
    
    print("="*50)
