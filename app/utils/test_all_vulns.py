#!/usr/bin/env python3
"""Test all types of vulnerabilities"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.utils.scanner import UniversalScanner

print("="*70)
print("COMPREHENSIVE VULNERABILITY TEST")
print("="*70)

test_cases = [
    ("Python SQL Injection + Pickle RCE", '''
import sqlite3
import pickle
import base64

SECRET_KEY = "VAST_DEBUG_KEY_12345"

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()

def load_data(data):
    return pickle.loads(base64.b64decode(data))

API_KEY = "sk_live_1234567890"
'''),
    
    ("C Buffer Overflow + Command Injection", '''
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable(char *input) {
    char buffer[10];
    strcpy(buffer, input);
}

int main() {
    char cmd[100];
    printf("Enter command: ");
    gets(cmd);
    system(cmd);
    return 0;
}
'''),
    
    ("JavaScript XSS + Eval Injection", '''
function displayMessage(userInput) {
    document.getElementById("output").innerHTML = userInput;
    eval(userInput);
    setTimeout("console.log(" + userInput + ")", 1000);
}

const API_SECRET = "ghp_1234567890abcdef";
'''),
    
    ("Hardcoded Secrets Only", '''
# Configuration file with secrets
DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "AKIAIOSFODNN7EXAMPLE"
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----"
'''),
]

for test_name, code in test_cases:
    print(f"\n{'='*50}")
    print(f"TEST: {test_name}")
    print(f"{'='*50}")
    
    results = UniversalScanner.scan_code(code, 'test.txt')
    
    print(f"Total findings: {results['total_findings']}")
    print(f"Severity breakdown: {results['by_severity']}")
    
    if results['details']:
        print("\nTop findings:")
        for i, finding in enumerate(results['details'][:3], 1):
            print(f"  {i}. [{finding['severity'].upper()}] {finding['message'][:60]}...")
    else:
        print("No findings!")
    
    time.sleep(1)

print(f"\n{'='*70}")
print("TEST COMPLETE")
print(f"{'='*70}")
