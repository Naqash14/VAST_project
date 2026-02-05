#!/usr/bin/env python3
"""Test your specific vulnerable code"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.utils.scanner import UniversalScanner

# Your exact test code
your_code = '''import sqlite3
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

print("Testing your vulnerable code...")
print("="*60)

results = UniversalScanner.scan_code(your_code, 'test.py')

print(f"\nRESULTS:")
print(f"Total findings: {results['total_findings']}")
print(f"Severity breakdown: {results['by_severity']}")

if results['details']:
    print("\nDETAILED FINDINGS:")
    for i, finding in enumerate(results['details'], 1):
        print(f"\n{i}. [{finding['severity'].upper()}]")
        print(f"   Type: {finding['type']}")
        print(f"   Source: {finding['source']}")
        print(f"   Line {finding['line']}: {finding['message']}")
        if finding.get('code_snippet'):
            print(f"   Code: {finding['code_snippet']}")
else:
    print("\nNO FINDINGS DETECTED!")
    print("This is unexpected. Let's debug...")
    
    # Manual check
    print("\nMANUAL CHECKS:")
    lines = your_code.split('\n')
    for i, line in enumerate(lines, 1):
        if 'SECRET_KEY = "' in line:
            print(f"Line {i}: Found hardcoded secret")
        if "query = \"SELECT" in line and "+ user_id" in line:
            print(f"Line {i}: Found SQL injection pattern")
        if "pickle.loads" in line:
            print(f"Line {i}: Found pickle deserialization")

print("\n" + "="*60)
print("If UniversalScanner doesn't find vulnerabilities,")
print("it will fall back to pattern matching which should catch them.")
