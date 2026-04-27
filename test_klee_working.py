from app.utils.symbolic_analyzer import SymbolicAnalyzer

# This code WILL trigger KLEE
test_code = '''
#include <klee/klee.h>
#include <assert.h>

int main() {
    int x;
    klee_make_symbolic(&x, sizeof(x), "x");
    
    if (x > 10) {
        assert(x <= 10);
    }
    return 0;
}
'''

analyzer = SymbolicAnalyzer()
result = analyzer.analyze(test_code, 'c')

print(f"\n{'='*50}")
print("RESULTS")
print(f"{'='*50}")
print(f"Findings found: {result.get('total_findings', 0)}")
for f in result.get('findings', []):
    print(f"  {f.get('message')}")
