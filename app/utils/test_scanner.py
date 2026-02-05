#!/usr/bin/env python3
import subprocess
import json
import tempfile
import os

def test_semgrep_directly():
    print("Testing Semgrep directly...")
    
    # Test 1: Check if semgrep is installed
    try:
        result = subprocess.run(['semgrep', '--version'], 
                              capture_output=True, text=True)
        print(f"Semgrep version: {result.stdout.strip()}")
    except Exception as e:
        print(f"Semgrep not found: {e}")
        return
    
    # Test 2: Create vulnerable code to test
    vulnerable_code = """
import sqlite3
import os
import pickle

# SQL Injection vulnerable code
def get_user_vulnerable(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

# Command injection vulnerable code
def run_command_vulnerable(cmd):
    # VULNERABLE: Direct shell command execution
    os.system(f"echo {cmd}")

# Pickle deserialization vulnerable code
def load_data_vulnerable(data):
    # VULNERABLE: Unsafe pickle loading
    return pickle.loads(data)

# Hardcoded password
password = "admin123"

# Debug output
print("Running vulnerable functions...")
result = get_user_vulnerable("1")
print(f"get_user_vulnerable: {result}")
"""
    
    # Save to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(vulnerable_code)
        temp_file = f.name
    
    print(f"\nCreated test file: {temp_file}")
    print("Test code contains:")
    print("1. SQL Injection (f-string in SQL)")
    print("2. Command Injection (os.system)")
    print("3. Pickle deserialization (pickle.loads)")
    print("4. Hardcoded password")
    
    # Test with basic semgrep
    print("\nRunning semgrep with 'auto' config...")
    cmd = ['semgrep', '--config', 'auto', '--json', temp_file]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    print(f"Return code: {result.returncode}")
    print(f"Stdout length: {len(result.stdout)}")
    print(f"Stderr: {result.stderr}")
    
    if result.stdout:
        try:
            findings = json.loads(result.stdout)
            print(f"\nFindings JSON keys: {findings.keys() if findings else 'Empty'}")
            
            if 'results' in findings and findings['results']:
                print(f"\nFound {len(findings['results'])} issues:")
                for i, finding in enumerate(findings['results'], 1):
                    print(f"\n{i}. {finding.get('check_id', 'Unknown')}")
                    print(f"   Message: {finding.get('extra', {}).get('message', 'No message')}")
                    print(f"   Severity: {finding.get('extra', {}).get('severity', 'Unknown')}")
                    print(f"   Line: {finding.get('start', {}).get('line', 'Unknown')}")
            else:
                print("\nNo issues found by semgrep!")
                
                # Try specific rules
                print("\nTrying specific security rules...")
                cmd2 = ['semgrep', '--config', 'p/security-audit', '--json', temp_file]
                result2 = subprocess.run(cmd2, capture_output=True, text=True)
                
                if result2.stdout:
                    findings2 = json.loads(result2.stdout)
                    if 'results' in findings2 and findings2['results']:
                        print(f"Found {len(findings2['results'])} issues with security-audit:")
                        for i, finding in enumerate(findings2['results'], 1):
                            print(f"\n{i}. {finding.get('check_id', 'Unknown')}")
                            print(f"   Message: {finding.get('extra', {}).get('message', 'No message')}")
                    else:
                        print("No issues found with security-audit either!")
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON: {e}")
            print(f"Raw output: {result.stdout[:500]}")
    
    # Clean up
    os.unlink(temp_file)
    print(f"\nDeleted test file: {temp_file}")

if __name__ == "__main__":
    test_semgrep_directly()
