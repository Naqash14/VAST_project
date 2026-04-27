#!/usr/bin/env python3
from app.utils.hybrid_analyzer import HybridAnalyzer

# C code with multiple vulnerabilities
c_code = '''
#include <stdlib.h>
#include <string.h>

void test(char *input, int mode) {
    system(input);  // Static finds
    char *ptr = malloc(100);
    if (mode == 1) {
        free(ptr);
        strcpy(ptr, input);  // Symbolic finds (use-after-free)
    }
    if (mode == 2) {
        free(ptr);
        free(ptr);  // Symbolic finds (double free)
    }
    int result = 100 / (mode - 1);  // Fuzz finds (division by zero)
}
'''

analyzer = HybridAnalyzer()
result = analyzer.analyze(c_code, 'c')

print("\n" + "="*60)
print("HYBRID ANALYSIS RESULTS")
print("="*60)
print(f"Total Findings: {result['summary']['total_findings']}")
print(f"  Critical: {result['summary']['critical']}")
print(f"  High: {result['summary']['high']}")
print(f"  Medium: {result['summary']['medium']}")
print(f"  Low: {result['summary']['low']}")

print("\nFindings by Source:")
static_count = len(result['static_analysis'].get('details', []))
symbolic_count = len(result['symbolic_analysis'].get('findings', []))
fuzz_count = len(result['fuzz_testing'].get('findings', []))

print(f"  Static: {static_count} findings")
print(f"  Symbolic: {symbolic_count} findings")
print(f"  Fuzz: {fuzz_count} findings")
