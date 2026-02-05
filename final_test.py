#!/usr/bin/env python3
"""Final test before restarting server"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Final test of UniversalScanner...")
print("="*60)

# Import directly
from app.utils.scanner import UniversalScanner

# Your exact test code
test_code = '''import sqlite3
import pickle
import base64

# VAST Security Test Case: Web & Logic Vulnerabilities
# 1. Hardcoded Secret (Security Risk)
SECRET_KEY = "VAST_DEBUG_KEY_12345"

def get_user_data(user_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    
    # VULNERABILITY: SQL Injection
    # User input is concatenated directly into the query.
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()

def load_session(session_data):
    # VULNERABILITY: Insecure Deserialization
    # 'pickle.loads' on untrusted data can lead to Remote Code Execution (RCE).
    data = base64.b64decode(session_data)
    return pickle.loads(data)

if __name__ == "__main__":
    # Simulate untrusted user input
    malicious_input = "1' OR '1'='1"
    get_user_data(malicious_input)
'''

print("\nScanning your code...")
results = UniversalScanner.scan_code(test_code, 'test.py')

print(f"\nFINDINGS: {results['total_findings']}")
for severity, count in results['by_severity'].items():
    if count > 0:
        print(f"  {severity.upper()}: {count}")

if results['details']:
    print("\nDETAILS:")
    for i, finding in enumerate(results['details'], 1):
        print(f"\n{i}. [{finding['severity'].upper()}] {finding['type']}")
        print(f"   {finding['message']}")
        print(f"   Line {finding['line']}: {finding.get('code_snippet', '')}")
else:
    print("\nWARNING: No findings detected!")
    print("The scanner should find:")
    print("1. Hardcoded secret (SECRET_KEY)")
    print("2. SQL injection (query = ... + user_id)")
    print("3. Insecure deserialization (pickle.loads)")

print("\n" + "="*60)
print("If this shows 0 findings, there's an issue with the scanner.")
print("Otherwise, restart the server and test in browser.")
