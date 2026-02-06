    # User programs embedded as raw machine code
    # These run in U-mode and can only interact with the kernel via ecall

    .section .rodata
    .align 4

    #---------------------------------------------------------------------------
    # User program: "hello" - prints "User OK!\n" via SYS_WRITE and exits
    #---------------------------------------------------------------------------
    .globl _user_hello_start
    .globl _user_hello_end
_user_hello_start:
    # Build the string "User OK!\n" on the stack
    addi    sp, sp, -16         # Allocate stack space
    li      t0, 0x55            # 'U'
    sb      t0, 0(sp)
    li      t0, 0x73            # 's'
    sb      t0, 1(sp)
    li      t0, 0x65            # 'e'
    sb      t0, 2(sp)
    li      t0, 0x72            # 'r'
    sb      t0, 3(sp)
    li      t0, 0x20            # ' '
    sb      t0, 4(sp)
    li      t0, 0x4f            # 'O'
    sb      t0, 5(sp)
    li      t0, 0x4b            # 'K'
    sb      t0, 6(sp)
    li      t0, 0x21            # '!'
    sb      t0, 7(sp)
    li      t0, 0x0a            # '\n'
    sb      t0, 8(sp)

    # SYS_WRITE(fd=1, buf=sp, len=9)
    li      a7, 64              # SYS_WRITE
    li      a0, 1               # fd = stdout
    mv      a1, sp              # buf = stack pointer
    li      a2, 9               # len = 9
    ecall

    # SYS_EXIT(0)
    li      a7, 93              # SYS_EXIT
    li      a0, 0               # exit code
    ecall

    # Should never reach here
    j       .
_user_hello_end:

    #---------------------------------------------------------------------------
    # User program: "getpid" - gets PID via syscall, writes it, and exits
    #---------------------------------------------------------------------------
    .globl _user_getpid_start
    .globl _user_getpid_end
_user_getpid_start:
    # SYS_GETPID
    li      a7, 172             # SYS_GETPID
    ecall
    # a0 = pid

    # Build string "PID=X\n" on stack (X is single digit for simplicity)
    addi    sp, sp, -16
    li      t0, 0x50            # 'P'
    sb      t0, 0(sp)
    li      t0, 0x49            # 'I'
    sb      t0, 1(sp)
    li      t0, 0x44            # 'D'
    sb      t0, 2(sp)
    li      t0, 0x3d            # '='
    sb      t0, 3(sp)
    # Convert pid (a0) to ASCII digit: add '0'
    addi    t0, a0, 0x30
    sb      t0, 4(sp)
    li      t0, 0x0a            # '\n'
    sb      t0, 5(sp)

    # SYS_WRITE(fd=1, buf=sp, len=6)
    li      a7, 64              # SYS_WRITE
    li      a0, 1               # fd = stdout
    mv      a1, sp              # buf
    li      a2, 6               # len
    ecall

    # SYS_EXIT(0)
    li      a7, 93              # SYS_EXIT
    li      a0, 0
    ecall

    j       .
_user_getpid_end:

    #---------------------------------------------------------------------------
    # User program: "shell" - interactive command shell
    #---------------------------------------------------------------------------
    .globl _user_shell_start
    .globl _user_shell_end
    .align 4
_user_shell_start:
    .incbin "user/shell/target/riscv64gc-unknown-none-elf/release/shell.bin"
_user_shell_end:
