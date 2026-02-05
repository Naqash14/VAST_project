#!/bin/bash

echo "=== VAST Scanner Quick Test ==="
echo ""

# Test 1: Python SQL Injection
echo "Test 1: Python SQL Injection"
cat > test1.py << 'PYEOF'
import sqlite3

def vulnerable_query(user_id):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()

# Command injection
import os
def run_command(cmd):
    os.system("echo " + cmd)

# Hardcoded secret
API_KEY = "sk_live_1234567890"
PYEOF

echo "Running semgrep on Python file..."
semgrep scan --config auto --json test1.py | python3 -c "
import json, sys
data = json.load(sys.stdin)
if 'results' in data and data['results']:
    print(f'Found {len(data[\"results\"])} issues:')
    for r in data['results'][:3]:
        print(f'  - {r[\"check_id\"]}: {r[\"extra\"][\"message\"][:50]}...')
else:
    print('No issues found')
"
rm test1.py

echo ""
echo "Test 2: C Buffer Overflow"
cat > test2.c << 'CEOF'
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buffer[10];
    strcpy(buffer, input);
}

int main() {
    char input[100];
    printf("Enter: ");
    gets(input);
    vulnerable(input);
    return 0;
}
CEOF

echo "Running semgrep on C file..."
semgrep scan --config p/c --json test2.c | python3 -c "
import json, sys
data = json.load(sys.stdin)
if 'results' in data and data['results']:
    print(f'Found {len(data[\"results\"])} issues:')
    for r in data['results'][:3]:
        print(f'  - {r[\"check_id\"]}: {r[\"extra\"][\"message\"][:50]}...')
else:
    print('No issues found')
"
rm test2.c

echo ""
echo "=== Testing ForceScanner Directly ==="
python3 -c "
import sys
sys.path.insert(0, '.')
from app.utils.scanner import ForceScanner

# Test Python
print('\\nTesting ForceScanner with Python code...')
code = '''
import sqlite3
def test(id):
    conn = sqlite3.connect(\"test.db\")
    cursor = conn.cursor()
    cursor.execute(\"SELECT * FROM users WHERE id = \" + id)
    return cursor.fetchone()
'''
result = ForceScanner.scan_code(code, 'test.py')
print(f'Findings: {result[\"total_findings\"]}')
print(f'Severities: {result[\"by_severity\"]}')

# Test C
print('\\nTesting ForceScanner with C code...')
c_code = '''
#include <string.h>
void test(char *input) {
    char buffer[10];
    strcpy(buffer, input);
}
'''
result = ForceScanner.scan_code(c_code, 'test.c')
print(f'Findings: {result[\"total_findings\"]}')
print(f'Severities: {result[\"by_severity\"]}')
"

echo ""
echo "=== Test Complete ==="
