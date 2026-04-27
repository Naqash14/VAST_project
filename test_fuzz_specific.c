#include <stdio.h>
#include <stdlib.h>

// STATIC WON'T FIND: Integer overflow depends on input value
// SYMBOLIC WON'T FIND: Too many paths to explore
// FUZZ SHOULD FIND: Extreme values cause overflow
int vulnerable_multiply(int a, int b) {
    return a * b;  // Overflow when a*b > INT_MAX
}

// STATIC WON'T FIND: Division by zero depends on input
// SYMBOLIC WON'T FIND: Path-specific
// FUZZ SHOULD FIND: Zero divisor causes crash
int vulnerable_divide(int a, int b) {
    return a / b;  // Crash when b == 0
}

// STATIC WON'T FIND: Array bounds depend on input
// SYMBOLIC WON'T FIND: Too many possibilities
// FUZZ SHOULD FIND: Out-of-bounds access
char vulnerable_array_access(char *arr, int index, int size) {
    return arr[index];  // Crash when index >= size
}

void test_function(char *input, int mode) {
    int val = atoi(input);
    
    if (mode == 1) {
        vulnerable_multiply(val, val);
    } else if (mode == 2) {
        vulnerable_divide(100, val);
    } else if (mode == 3) {
        char arr[10];
        vulnerable_array_access(arr, val, 10);
    }
}
