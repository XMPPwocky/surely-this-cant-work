# 0016: IPC Message structs cause excessive stack pressure

**Reported:** 2026-02-20
**Status:** Closed
**Severity:** MEDIUM
**Subsystem:** ipc (user-space IPC, std runtime)

## Symptoms

Programs with deep IPC call chains during initialization (e.g., fbcon)
can overflow the user stack. Each `Message` struct is 1080 bytes, and
IPC round-trips typically allocate two (send + recv) on the stack per
call. The std runtime `connect_to_service` alone uses 2160 bytes of
stack for two Messages.

## Root Cause

`Message::new()` creates a 1080-byte struct on the stack. IPC helpers
in both the userlib (`lib/rvos/`) and std PAL (`vendor/rust/...`) used
`let mut msg = Message::new()` for every send and receive operation,
placing 1-2 Messages (1080-2160 bytes) on the stack per call.

## Fix

Added `Message::boxed()` to both the userlib message module and the std
PAL ipc module. This uses `alloc_zeroed` + `Box::from_raw` to allocate
a zeroed Message directly on the heap without placing it on the stack
first, then sets the `caps` array to `NO_CAP` (since `alloc_zeroed`
gives all-zeros but caps should be `usize::MAX`).

Replaced all `Message::new()` calls with `Message::boxed()` in:
- `lib/rvos/src/`: channel.rs, transport.rs, tty.rs, socket.rs
- `vendor/rust/.../std/`: ipc.rs, stdio/rvos.rs, args/rvos.rs,
  fs/rvos.rs, net/connection/rvos/ (mod.rs, tcpstream.rs, udp.rs)

Also changed `Channel<S,R>.recv_buf` from `Message` to `Box<Message>`
to avoid embedding 1080 bytes in every Channel struct.

Each IPC call now uses ~16 bytes of stack (the Box pointer) instead of
1080, reducing per-call stack usage by ~98%.

## Verification

`make test-quick` passes (69/69 tests). `make clippy` clean.
`make build-std-lib && make build` both succeed.

## Lessons Learned

Large structs (> ~256 bytes) should be heap-allocated in IPC paths,
especially in user-space where stack is limited to 64 KiB. The
`alloc_zeroed` + `Box::from_raw` pattern avoids the Rust
`Box::new(large_struct)` pitfall where the struct is briefly placed on
the stack before being moved to the heap.
