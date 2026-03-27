#!/usr/bin/env python3
import os
import psycopg2
from app import create_app, db
from app.models import User

def test_postgres_connection():
    print("Testing PostgreSQL Connection...")
    
    try:
        # Test direct connection
        conn = psycopg2.connect(
            database="vast_scanner",
            user="vast_user",
            password="secure_password",
            host="localhost"
        )
        print("✅ Direct PostgreSQL connection successful")
        conn.close()
        
        # Test Flask-SQLAlchemy connection
        app = create_app()
        with app.app_context():
            # Try to create tables
            db.create_all()
            print("✅ Tables created successfully")
            
            # Try to insert test user
            test_user = User(
                username='test_user',
                email='test@example.com',
                is_verified=True
            )
            test_user.set_password('Test@123')
            db.session.add(test_user)
            db.session.commit()
            print("✅ Test user inserted successfully")
            
            # Try to query
            users = User.query.all()
            print(f"✅ Found {len(users)} users in database")
            
            # Clean up
            db.session.delete(test_user)
            db.session.commit()
            print("✅ Test user deleted successfully")
            
        print("🎉 PostgreSQL is working perfectly!")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_postgres_connection()
