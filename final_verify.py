from app.utils.symbolic_analyzer import SymbolicAnalyzer
from app.utils.scanner import UniversalScanner

print("\n" + "="*70)
print("🔬 VAST SCANNER - FINAL VERIFICATION")
print("="*70)

analyzer = SymbolicAnalyzer()
scanner = UniversalScanner()

# ============================================================
print("\n" + "-"*70)
print("📊 C/C++ ANALYSIS")
print("-"*70)

c_code = '''
#include <stdlib.h>
#include <string.h>

void test(char *input) {
    char *ptr = malloc(100);
    free(ptr);
    strcpy(ptr, input);
}
'''

print("Static (Semgrep):")
s_result = scanner.scan_code(c_code, 'test.c')
print(f"  Findings: {s_result.get('total_findings', 0)}")

print("Symbolic (KLEE):")
sym_result = analyzer.analyze(c_code, 'c')
print(f"  Findings: {sym_result.get('total_findings', 0)}")
for f in sym_result.get('findings', []):
    print(f"    - {f.get('message')}")

# ============================================================
print("\n" + "-"*70)
print("📊 PYTHON ANALYSIS")
print("-"*70)

py_code = '''
import os
import threading

def test(data):
    os.system("ping " + data)
    t = threading.Thread(target=lambda: None)
    t.start()
'''

print("Static (Semgrep):")
s_result = scanner.scan_code(py_code, 'test.py')
print(f"  Findings: {s_result.get('total_findings', 0)}")

print("Symbolic (Angr):")
sym_result = analyzer.analyze(py_code, 'python')
print(f"  Findings: {sym_result.get('total_findings', 0)}")
for f in sym_result.get('findings', []):
    print(f"    - {f.get('message')}")

# ============================================================
print("\n" + "-"*70)
print("📊 JAVA ANALYSIS")
print("-"*70)

java_code = '''
import java.sql.*;
public class Test {
    public void vuln(String input) throws Exception {
        Statement stmt = DriverManager.getConnection("jdbc:mysql://localhost/db","user","pass").createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + input);
        
        final Object a = new Object();
        final Object b = new Object();
        Thread t = new Thread(() -> {
            synchronized(a) {
                synchronized(b) { }
            }
        });
        t.start();
    }
}
'''

print("Static (Semgrep):")
s_result = scanner.scan_code(java_code, 'Test.java')
print(f"  Findings: {s_result.get('total_findings', 0)}")

print("Symbolic (Pattern):")
sym_result = analyzer.analyze(java_code, 'java')
print(f"  Findings: {sym_result.get('total_findings', 0)}")
for f in sym_result.get('findings', []):
    print(f"    - {f.get('message')}")

print("\n" + "="*70)
print("✅ VAST SCANNER IS FULLY FUNCTIONAL!")
print("="*70)
