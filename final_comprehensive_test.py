"""
Final Comprehensive Test - All Vulnerability Types
Tests Static, Symbolic, and Fuzz on a single code sample
"""

from app.utils.scanner import UniversalScanner
from app.utils.symbolic_analyzer import SymbolicAnalyzer
from app.utils.fuzz_tester import FuzzTester

# Test code with ALL vulnerability types
test_code = '''
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ===== VULNERABILITY 1: COMMAND INJECTION =====
void command_injection(char *input) {
    system(input);
}

// ===== VULNERABILITY 2: BUFFER OVERFLOW =====
void buffer_overflow(char *input) {
    char buffer[10];
    strcpy(buffer, input);
}

// ===== VULNERABILITY 3: USE-AFTER-FREE =====
void use_after_free(char *input, int mode) {
    char *ptr = malloc(100);
    if (mode == 1) {
        free(ptr);
        strcpy(ptr, input);
    }
}

// ===== VULNERABILITY 4: DOUBLE FREE =====
void double_free(char *input, int mode) {
    char *ptr = malloc(100);
    if (mode == 2) {
        free(ptr);
        free(ptr);
    }
}

// ===== VULNERABILITY 5: INTEGER OVERFLOW =====
int integer_overflow(int a, int b) {
    return a * b;
}

// ===== VULNERABILITY 6: DIVISION BY ZERO =====
int division_by_zero(int a, int b) {
    return a / b;
}

// ===== VULNERABILITY 7: MEMORY LEAK =====
void memory_leak() {
    char *ptr = malloc(100);
}

// ===== VULNERABILITY 8: ARRAY BOUNDS =====
char array_bounds(char *arr, int idx) {
    return arr[idx];
}

void test_function(char *input, int mode) {
    command_injection(input);
    buffer_overflow(input);
    use_after_free(input, mode);
    double_free(input, mode);
    integer_overflow(mode, mode + 1000);
    division_by_zero(mode, mode - 1);
    memory_leak();
    char test_arr[10];
    array_bounds(test_arr, mode * 10);
}
'''

print("="*70)
print("FINAL COMPREHENSIVE HYBRID ANALYSIS TEST")
print("="*70)

# Static Analysis
print("\n STATIC ANALYSIS (Semgrep + Patterns)")
print("-"*50)
scanner = UniversalScanner()
static_result = scanner.scan_code(test_code, 'test.c')
print("Total Findings:", static_result.get("total_findings", 0))
for f in static_result.get("details", []):
    print("   🔴", f.get("message", "")[:90])

# Symbolic Analysis
print("\n SYMBOLIC ANALYSIS (KLEE)")
print("-"*50)
symbolic = SymbolicAnalyzer()
sym_result = symbolic.analyze(test_code, 'c')
print("Total Findings:", sym_result.get("total_findings", 0))
for f in sym_result.get("findings", []):
    print("   🔴", f.get("message", "")[:90])

# Fuzz Testing
print("\n FUZZ TESTING (libFuzzer)")
print("-"*50)
fuzzer = FuzzTester()
fuzz_result = fuzzer.fuzz(test_code, 'c')
print("Total Findings:", fuzz_result.get("total_findings", 0))
for f in fuzz_result.get("findings", []):
    print("   🔴", f.get("message", "")[:90])

print("\n" + "="*70)
print("TEST COMPLETE - Ready for Web Deployment!")
print("="*70)
