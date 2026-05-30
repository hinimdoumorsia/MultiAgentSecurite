// RUST - Les vulnérabilités mémoire nécessitent 'unsafe'
// Ces exemples sont pour TESTER votre analyseur

// 1. BUFFER OVERFLOW (via unsafe)
fn buffer_overflow() {
    unsafe {
        let mut buffer = vec![0u8; 10];
        let large = vec![65u8; 100];  // 'A' * 100
        std::ptr::copy_nonoverlapping(
            large.as_ptr(),
            buffer.as_mut_ptr(),
            100  // VULN: writing past buffer bounds
        );
    }
}

// 2. USE AFTER FREE (via raw pointer)
fn use_after_free() {
    let ptr = Box::into_raw(Box::new(42));
    unsafe {
        drop(Box::from_raw(ptr));  // free
        println!("{}", *ptr);  // VULN: use after free
    }
}

// 3. DOUBLE FREE
fn double_free() {
    let ptr = Box::into_raw(Box::new(42));
    unsafe {
        drop(Box::from_raw(ptr));
        drop(Box::from_raw(ptr));  // VULN: double free
    }
}

// 4. MEMORY LEAK (forget)
fn memory_leak() {
    let leak = Box::new(42);
    std::mem::forget(leak);  // VULN: memory leak
}

// 5. MEMORY LEAK (cycle with Rc)
use std::rc::Rc;
use std::cell::RefCell;

struct Node {
    next: RefCell<Option<Rc<Node>>>,
}

fn memory_leak_cycle() {
    let first = Rc::new(Node { next: RefCell::new(None) });
    let second = Rc::new(Node { next: RefCell::new(None) });
    *first.next.borrow_mut() = Some(Rc::clone(&second));
    *second.next.borrow_mut() = Some(Rc::clone(&first));
    // VULN: reference cycle - memory leak (needs weak)
}

// 6. NULL DEREFERENCE (via raw pointer)
fn null_dereference() {
    let ptr: *const i32 = std::ptr::null();
    unsafe {
        println!("{}", *ptr);  // VULN: null dereference
    }
}

// 7. DANGLING POINTER
fn dangling_pointer() -> *const i32 {
    let local = 42;
    &local as *const i32  // VULN: returning pointer to stack
}

// 8. OUT OF BOUNDS (safe Rust panics, but unsafe bypasses)
fn out_of_bounds_unsafe() {
    let vec = vec![1,2,3,4,5];
    unsafe {
        println!("{}", vec.get_unchecked(10));  // VULN: out of bounds
    }
}

// 9. UNINITIALIZED MEMORY READ
fn uninitialized_read() {
    unsafe {
        let ptr: *mut i32 = std::alloc::alloc(
            std::alloc::Layout::new::<i32>()
        ) as *mut i32;
        println!("{}", *ptr);  // VULN: reading uninitialized memory
        std::alloc::dealloc(ptr as *mut u8, std::alloc::Layout::new::<i32>());
    }
}

// 10. MISMATCHED ALLOCATION/DEALLOCATION
fn mismatched_alloc() {
    unsafe {
        let ptr = std::alloc::alloc(std::alloc::Layout::new::<i32>());
        drop(Box::from_raw(ptr as *mut i32));  // VULN: mismatched free
    }
}

fn main() {
    println!("=== MEMORY VULNERABILITY TEST SUITE (RUST UNSAFE) ===");
    
    buffer_overflow();
    use_after_free();
    double_free();
    memory_leak();
    memory_leak_cycle();
    null_dereference();
    out_of_bounds_unsafe();
    uninitialized_read();
    
    let dangling = dangling_pointer();
    unsafe { println!("{}", *dangling); }  // VULN: dangling pointer
}