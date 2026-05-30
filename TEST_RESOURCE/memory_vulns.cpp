#include <iostream>
#include <cstring>
#include <memory>
#include <vector>

class VulnerableClass {
public:
    int* data;
    
    VulnerableClass(int size) {
        data = new int[size];
    }
    
    ~VulnerableClass() {
        delete[] data;
    }
};

// 1. BUFFER OVERFLOW
void buffer_overflow_cpp() {
    char buffer[10];
    std::string large(100, 'A');
    strcpy(buffer, large.c_str());  // VULN: buffer overflow
}

// 2. USE AFTER FREE (raw pointer)
void use_after_free_raw() {
    int* ptr = new int(42);
    delete ptr;
    *ptr = 100;  // VULN: use after free
}

// 3. USE AFTER FREE (smart pointer misuse)
void use_after_free_smart() {
    std::unique_ptr<int> ptr = std::make_unique<int>(42);
    int* raw = ptr.get();
    ptr.reset();
    *raw = 100;  // VULN: use after free via raw pointer
}

// 4. DOUBLE FREE
void double_free_cpp() {
    int* ptr = new int(42);
    delete ptr;
    delete ptr;  // VULN: double free
}

// 5. MEMORY LEAK (raw pointer)
void memory_leak_raw() {
    int* leak = new int[1000];
    // VULN: never deleted
    leak[0] = 1;
}

// 6. MEMORY LEAK (exception safety)
void memory_leak_exception() {
    int* leak = new int[1000];
    throw std::runtime_error("exception");  // VULN: leak if exception thrown
    delete[] leak;
}

// 7. NULL DEREFERENCE
void null_dereference_cpp() {
    int* ptr = nullptr;
    *ptr = 42;  // VULN: null dereference
}

// 8. DANGLING REFERENCE
int& dangling_reference() {
    int local = 42;
    return local;  // VULN: returning reference to stack
}

// 9. ARRAY OUT OF BOUNDS
void array_out_of_bounds() {
    std::vector<int> vec(5);
    for(int i = 0; i <= 5; i++) {
        vec[i] = i;  // VULN: out of bounds at i=5 (debug mode may crash)
    }
}

// 10. INVALID ITERATOR
void invalid_iterator() {
    std::vector<int> vec = {1,2,3,4,5};
    auto it = vec.begin();
    vec.push_back(6);  // may reallocate
    *it = 10;  // VULN: iterator invalidated
}

// 11. DOUBLE DELETE (shared_ptr cycle not really, but raw delete)
void double_delete_raw() {
    int* ptr = new int(42);
    delete ptr;
    delete ptr;  // VULN: double delete
}

// 12. VIRTUAL DESTRUCTOR MISSING
class Base {
public:
    ~Base() {}  // VULN: non-virtual destructor
};

class Derived : public Base {
public:
    int* buffer;
    Derived() { buffer = new int[100]; }
    ~Derived() { delete[] buffer; }
};

void missing_virtual_dtor() {
    Base* obj = new Derived();
    delete obj;  // VULN: Derived destructor not called, memory leak
}

int main() {
    std::cout << "=== MEMORY VULNERABILITY TEST SUITE (C++) ===" << std::endl;
    
    buffer_overflow_cpp();
    use_after_free_raw();
    use_after_free_smart();
    double_free_cpp();
    memory_leak_raw();
    null_dereference_cpp();
    array_out_of_bounds();
    invalid_iterator();
    double_delete_raw();
    missing_virtual_dtor();
    
    int& ref = dangling_reference();
    std::cout << ref << std::endl;  // VULN: dangling reference
    
    return 0;
}