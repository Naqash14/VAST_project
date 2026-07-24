#!/usr/bin/env python3
"""
Migrate tables to Railway PostgreSQL
Run this script to create tables and admin user
"""

import os
import sys
import psycopg2
from werkzeug.security import generate_password_hash

# Railway PostgreSQL connection string
DATABASE_URL = "postgresql://postgres:cZEGfLpNnQoIExicZcYHaeqNUdYgCYmf@sakura.proxy.rlwy.net:24516/railway"

def migrate():
    print("🔄 Connecting to Railway PostgreSQL...")
    
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        print("✅ Connected to database")
        
        # Create tables
        print("📊 Creating tables...")
        
        # User table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS "user" (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(200) NOT NULL,
                is_verified BOOLEAN DEFAULT FALSE,
                is_2fa_enabled BOOLEAN DEFAULT FALSE,
                is_admin BOOLEAN DEFAULT FALSE,
                profile_pic VARCHAR(200),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                login_attempts INTEGER DEFAULT 0
            )
        """)
        print("  ✅ user table created")
        
        # OTP table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS otp (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES "user"(id),
                email VARCHAR(120) NOT NULL,
                otp_code VARCHAR(6) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_used BOOLEAN DEFAULT FALSE,
                attempts INTEGER DEFAULT 0
            )
        """)
        print("  ✅ otp table created")
        
        # Project table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS project (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES "user"(id) NOT NULL,
                project_name VARCHAR(200) NOT NULL,
                code_content TEXT,
                filename VARCHAR(200),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("  ✅ project table created")
        
        # Scan result table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_result (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES "project"(id) NOT NULL,
                tool_name VARCHAR(50) NOT NULL,
                findings TEXT,
                severity VARCHAR(20) DEFAULT 'info',
                ai_analysis TEXT,
                ai_status VARCHAR(20) DEFAULT 'none',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("  ✅ scan_result table created")
        
        # Check if admin exists
        cursor.execute("SELECT * FROM \"user\" WHERE email = 'admin@vast.local'")
        admin = cursor.fetchone()
        
        if not admin:
            # Create admin user
            password_hash = generate_password_hash('Admin@123456')
            cursor.execute("""
                INSERT INTO "user" (username, email, password_hash, is_verified, is_admin)
                VALUES (%s, %s, %s, %s, %s)
            """, ('admin', 'admin@vast.local', password_hash, True, True))
            print("  ✅ Admin user created")
        else:
            print("  ✅ Admin user already exists")
        
        # Create test user
        cursor.execute("SELECT * FROM \"user\" WHERE email = 'bangashnaqash12@gmail.com'")
        test_user = cursor.fetchone()
        
        if not test_user:
            password_hash = generate_password_hash('naqash12@*')
            cursor.execute("""
                INSERT INTO "user" (username, email, password_hash, is_verified, is_admin)
                VALUES (%s, %s, %s, %s, %s)
            """, ('naqash', 'bangashnaqash12@gmail.com', password_hash, True, False))
            print("  ✅ Test user created")
        else:
            print("  ✅ Test user already exists")
        
        conn.commit()
        
        # Verify tables
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name
        """)
        tables = cursor.fetchall()
        print("\n📊 Tables in database:")
        for table in tables:
            print(f"  - {table[0]}")
        
        cursor.close()
        conn.close()
        
        print("\n✅ Migration complete!")
        print("   Admin email: admin@vast.local")
        print("   Admin password: Admin@123456")
        print("   Test email: bangashnaqash12@gmail.com")
        print("   Test password: naqash12@*")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    migrate()
