#!/usr/bin/env python3
"""
Database Reset Script
Run: python reset_db.py
"""

from app import create_app, db

def reset_database():
    print("=" * 50)
    print("🔄 Resetting Database")
    print("=" * 50)
    
    app = create_app()
    
    with app.app_context():
        try:
            # Drop all tables
            db.drop_all()
            print("✅ Tables dropped")
            
            # Create all tables
            db.create_all()
            print("✅ Tables created")
            
            # Verify tables
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            print(f"📊 Tables: {', '.join(tables)}")
            
            print("\n✅ Database reset complete!")
            
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    reset_database()
