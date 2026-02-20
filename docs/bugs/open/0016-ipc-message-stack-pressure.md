# 0016: IPC Message structs cause excessive stack pressure

**Reported:** 2026-02-20
**Status:** Open
**Severity:** MEDIUM
**Subsystem:** ipc (user-space IPC, std runtime)

## Symptoms

Programs with deep IPC call chains during initialization (e.g., fbcon)
can overflow the user stack. Each `Message` struct is 1080 bytes, and
IPC round-trips typically allocate two (send + recv) on the stack per
call. The std runtime `connect_to_service` alone uses 2160 bytes of
stack for two Messages.

fbcon's startup chain:
```
lang_start → init → stdio::init → connect_to_service("stdin")  [2160 B]
                  → connect_to_service("stdout")                [2160 B]
                  → args::init                                  [~2160 B]
           → main → println!("[fbcon] starting")  → send_write  [2160 B]
                  → connect_to_service("window")                [2160 B]
                  → Channel::send/recv (CreateWindow)           [2160 B]
                  → WindowClient::get_info / get_framebuffer    [2160 B]
```

While these are mostly sequential (stack frames freed between calls),
the cumulative depth at the deepest point — including function prologues,
format machinery, trait object dispatch, and compiler-generated code —
exceeded 32 KiB.

## Workaround

Bug 0015 fix increased `USER_STACK_PAGES` from 8 (32 KiB) to 16 (64 KiB),
giving adequate headroom. This costs an additional 32 KiB per user process.

## Proper Fix

Reduce per-call stack usage for IPC operations. Options:

1. **Heap-allocate Messages in std IPC helpers.** Replace
   `let mut msg = Message::new();` with `let mut msg = Box::new(Message::new());`
   in `connect_to_service`, `send_write`, `recv_read`. This moves 1080 bytes
   per Message from stack to heap.

2. **Shrink Message.** The 1024-byte data buffer is larger than most
   messages need. A two-tier approach (small inline buffer + heap overflow)
   could reduce the common case.

3. **Thread-local scratch buffer.** A single heap-allocated Message per
   thread, reused across IPC calls. Avoids repeated alloc/dealloc.

Option 1 is the simplest and would immediately reduce stack pressure.
After `Box::new(Message::new())`, each IPC call would use ~16 bytes of
stack (the Box pointer) instead of 1080.

**Note:** `Box::new(large_struct)` on current Rust nightly may still
briefly place the struct on the stack before moving to heap. Use
`alloc::alloc::alloc_zeroed` + `Box::from_raw` for zero-copy heap
allocation if this is a concern.

## Verification

(To be filled after fix — measure peak stack usage with/without fix.)
