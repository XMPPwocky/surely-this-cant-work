# Kernel Conventions

## Tagged Allocators

All heap allocations in the kernel must use a tagged allocator. Never use
bare `Vec::new()` or `VecDeque::new()` — always use `Vec::new_in(TAG_ALLOC)`
or `Vec::with_capacity_in(n, TAG_ALLOC)` with the appropriate pool tag.

This ensures every allocation is tracked under a 4-byte ASCII tag visible
via the shell `mem` command. Untagged allocations show up under `????`,
which should be minimized.

Existing tags and their meanings are documented in `docs/kernel-allocator-tags.md`.

To add a new tag, define a type alias and const in `kernel/src/mm/heap.rs`:

```rust
pub type MyAlloc = TaggedAlloc<{tag(b"MYTG")}>;
pub const MY_ALLOC: MyAlloc = TaggedAlloc;
```

Then use `Vec::new_in(MY_ALLOC)` in your data structures.

## DMA / Volatile Memory Access

All accesses to DMA shared memory (VirtIO descriptor tables, available rings,
used rings, and device-written data buffers) **must** use `read_volatile` /
`write_volatile`. Never create Rust references (`&T` / `&mut T`) to DMA
memory — use raw pointer field access via `core::ptr::addr_of[_mut]!`.

```rust
// CORRECT: volatile field access without creating a reference
let idx = unsafe { core::ptr::addr_of!((*ptr).idx).read_volatile() };

// WRONG: creates a shared reference to device-modified DMA memory
let used = unsafe { &*ptr };
let idx = used.idx;
```

DMA memory is external to Rust's memory model. The compiler may assume memory
behind `&T` doesn't change, and can cache or elide reads even across
`fence(SeqCst)`. `read_volatile` / `write_volatile` are the only guaranteed
way to access externally-modified memory. See bug 0004 for details.

## Blocking vs Non-blocking Channel Sends

Use **blocking sends** for any message the receiver must see (service
responses, init server messages, protocol steps). A dropped response hangs
the client. Use **non-blocking sends** only for fire-and-forget event
streams (mouse/keyboard input to window server) where drops are acceptable.

## Capability Transfer Ref Counting

Any cap placed in a message's `caps[]` MUST be inc_ref'd before sending.
Automatic paths: `translate_cap_for_send()` (user syscalls),
`KernelTransport::send()`, `send_ok_with_cap()`. Manual inc_ref required
for kernel tasks calling `channel_send_blocking` directly. Prefer RAII
wrappers per the root CLAUDE.md convention — these manual paths should be
migrated to RAII over time.

## Syscall Error Handling

All syscall handlers must return `SyscallResult` (= `Result<usize, SyscallError>`).
Never return raw sentinel values (`usize::MAX`, bare integer codes) — use the
`SyscallError` enum. See `kernel/src/arch/CLAUDE.md` for the full error code table.

The dispatch in `handle_syscall` converts Results to raw `usize` at the ABI
boundary via `result_to_a0()` (status-only syscalls) or `value_result_to_a0()`
(syscalls returning handles/addresses). Both include debug assertions to catch
success-value / error-code collisions.

## Kernel-internal Panic Policy

Functions taking kernel-internal IDs (endpoint IDs, SHM IDs) should
**panic** on invalid inputs — these indicate bugs, not runtime conditions.
Reserve `Result`/`Option` for legitimate runtime failures (resource
exhaustion, user-provided handles).
