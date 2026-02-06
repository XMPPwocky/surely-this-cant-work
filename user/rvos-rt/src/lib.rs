use core::arch::global_asm;

// Entry point: the ELF loader jumps here.
// We call the compiler-generated `main` (which calls lang_start -> user's fn main).
// After main returns, we exit via SYS_EXIT.
global_asm!(
    r#"
    .section .text.entry
    .globl _start
_start:
    # Set up a small initial stack frame (sp is set by the kernel)
    # Call the compiler-generated main function
    # rustc emits: fn main(argc: isize, argv: *const *const u8) -> isize
    li      a0, 0           # argc = 0
    li      a1, 0           # argv = null
    call    main
    # main returned in a0 — use it as exit code
    li      a7, 93          # SYS_EXIT
    ecall
    j       .
"#
);

// compiler-builtins-mem implementations needed by std
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        unsafe {
            *dest.add(i) = *src.add(i);
        }
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        unsafe {
            *dest.add(i) = c as u8;
        }
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dest as usize) <= (src as usize) {
        memcpy(dest, src, n)
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            unsafe {
                *dest.add(i) = *src.add(i);
            }
        }
        dest
    }
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = unsafe { *s1.add(i) };
        let b = unsafe { *s2.add(i) };
        if a != b {
            return a as i32 - b as i32;
        }
        i += 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn bcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    memcmp(s1, s2, n)
}

#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    while unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    len
}
