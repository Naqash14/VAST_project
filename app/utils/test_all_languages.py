#!/usr/bin/env python3
"""Test scanner with multiple languages"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.utils.scanner import ForceScanner

# Test cases for different languages
test_cases = [
    ("Python SQL Injection", "python", '''
import sqlite3
def get_user(user_id):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()
'''),
    
    ("C Buffer Overflow", "c", '''
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buffer[10];
    strcpy(buffer, input);
    printf("%s\\n", buffer);
}

int main() {
    char input[100];
    printf("Enter: ");
    gets(input);
    vulnerable(input);
    return 0;
}
'''),
    
    ("JavaScript XSS", "javascript", '''
function displayMessage(userInput) {
    document.getElementById("output").innerHTML = userInput;
    eval(userInput);
    setTimeout("console.log(" + userInput + ")", 1000);
}
'''),
    
    ("Java Command Injection", "java", '''
import java.io.*;

public class Test {
    public void runCommand(String input) throws IOException {
        Runtime.getRuntime().exec("ping " + input);
    }
}
'''),
    
    ("PHP SQL Injection", "php", '''
<?php
$conn = mysqli_connect("localhost", "user", "pass", "db");
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysqli_query($conn, $query);
?>
''')
]

print("Testing ForceScanner with multiple languages...")
print("="*60)

for test_name, language, code in test_cases:
    print(f"\nTest: {test_name}")
    print(f"Language: {language}")
    print("-"*40)
    
    results = ForceScanner.scan_code(code, f"test.{language}")
    
    print(f"Total findings: {results.get('total_findings', 0)}")
    print(f"By severity: {results.get('by_severity', {})}")
    
    if results.get('details'):
        print("Top findings:")
        for i, finding in enumerate(results['details'][:3], 1):
            print(f"  {i}. [{finding['severity'].upper()}] {finding['rule_id']}")
            print(f"     Line {finding['line']}: {finding['message'][:50]}...")
    else:
        print("No findings detected")
    
    print()

print("="*60)
print("Test completed!")
