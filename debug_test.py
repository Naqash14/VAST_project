#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')

from app import create_app
from app.models import Project
from app.utils.scanner import CodeScanner

app = create_app()

with app.app_context():
    # Test scanner directly
    scanner = CodeScanner('app/uploads')
    
    # Test with small code
    test_code = '''import sqlite3
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
'''
    
    print("Testing scanner with small code sample...")
    results = scanner.scan_with_semgrep(test_code)
    print(f"Results: {results}")
    print(f"Has error: {'error' in results}")
    if 'error' in results:
        print(f"Error: {results['error']}")
    else:
        print(f"Total findings: {results.get('total_findings', 0)}")
        print(f"By severity: {results.get('by_severity', {})}")
