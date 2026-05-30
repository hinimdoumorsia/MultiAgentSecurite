#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1. BUFFER OVERFLOW (stack)
void buffer_overflow_stack() {
    char buffer[10];
    char* large = malloc(100);
    memset(large, 'A', 99);
    large[99] = '\0';
    strcpy(buffer, large);  // VULN: buffer overflow
    free(large);
}

// 2. BUFFER OVERFLOW (heap)
void buffer_overflow_heap() {
    char* buffer = malloc(10);
    char* large = malloc(100);
    memset(large, 'B', 99);
    large[99] = '\0';
    strcpy(buffer, large);  // VULN: heap buffer overflow
    free(buffer);
    free(large);
}

// 3. USE AFTER FREE
void use_after_free() {
    int* ptr = malloc(sizeof(int));
    *ptr = 42;
    free(ptr);
    *ptr = 100;  // VULN: use after free
}

// 4. DOUBLE FREE
void double_free() {
    int* ptr = malloc(sizeof(int));
    free(ptr);
    free(ptr);  // VULN: double free
}

// 5. MEMORY LEAK
void memory_leak() {
    int* leak = malloc(1024);
    // VULN: never freed - memory leak
    leak[0] = 1;
}

// 6. NULL POINTER DEREFERENCE
void null_dereference() {
    int* ptr = NULL;
    *ptr = 42;  // VULN: null pointer dereference
}

// 7. UNINITIALIZED VARIABLE
void uninitialized_use() {
    int* ptr = malloc(sizeof(int));
    int value = *ptr;  // VULN: uninitialized read
    printf("%d\n", value);
    free(ptr);
}

// 8. OUT OF BOUNDS ACCESS
void out_of_bounds() {
    int arr[5];
    for(int i = 0; i <= 5; i++) {
        arr[i] = i;  // VULN: out of bounds at i=5
    }
}

// 9. RETURN OF STACK ADDRESS
int* return_stack_address() {
    int local = 42;
    return &local;  // VULN: returning pointer to stack
}

// 10. MISMATCHED ALLOCATION/DEALLOCATION
void mismatched_free() {
    int* ptr = new int(42);  // VULN: new but free (should be delete)
    free(ptr);
}

int main() {
    printf("=== MEMORY VULNERABILITY TEST SUITE (C) ===\n");
    
    buffer_overflow_stack();
    buffer_overflow_heap();
    use_after_free();
    double_free();
    memory_leak();
    null_dereference();
    uninitialized_use();
    out_of_bounds();
    
    int* bad_ptr = return_stack_address();
    printf("%d\n", *bad_ptr);  // VULN: stack memory invalid
    
    return 0;
}