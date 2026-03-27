#!/usr/bin/env python3
"""
Database Migration Script: SQLite to PostgreSQL
Run this to migrate existing data to PostgreSQL
"""

import os
import sqlite3
import psycopg2
from datetime import datetime

def migrate_data():
    print("🔄 Starting database migration...")
    
    # Connect to SQLite
    sqlite_conn = sqlite3.connect('vast.db')
    sqlite_cursor = sqlite_conn.cursor()
    
    # Connect to PostgreSQL
    pg_conn = psycopg2.connect(
        database="vast_scanner",
        user="vast_user",
        password="secure_password",
        host="localhost"
    )
    pg_cursor = pg_conn.cursor()
    
    try:
        # Migrate Users
        print("Migrating users...")
        sqlite_cursor.execute("SELECT * FROM user")
        users = sqlite_cursor.fetchall()
        
        for user in users:
            pg_cursor.execute("""
                INSERT INTO user (id, username, email, password_hash, is_verified, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, user)
        
        # Migrate Projects
        print("Migrating projects...")
        sqlite_cursor.execute("SELECT * FROM project")
        projects = sqlite_cursor.fetchall()
        
        for project in projects:
            pg_cursor.execute("""
                INSERT INTO project (id, user_id, project_name, code_content, filename, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, project)
        
        # Migrate Scan Results
        print("Migrating scan results...")
        sqlite_cursor.execute("SELECT * FROM scan_result")
        scans = sqlite_cursor.fetchall()
        
        for scan in scans:
            pg_cursor.execute("""
                INSERT INTO scan_result (id, project_id, tool_name, findings, severity, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, scan)
        
        pg_conn.commit()
        print(f"✅ Migration complete! Migrated:")
        print(f"   - {len(users)} users")
        print(f"   - {len(projects)} projects")
        print(f"   - {len(scans)} scan results")
        
    except Exception as e:
        pg_conn.rollback()
        print(f"❌ Migration failed: {e}")
        
    finally:
        sqlite_conn.close()
        pg_conn.close()

if __name__ == "__main__":
    migrate_data()
