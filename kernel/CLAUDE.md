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

Use **blocking sends** (`channel_send_blocking` / `sys_chan_send_blocking`)
for any message where the receiver must eventually see it:

- **Kernel service responses** (gpu, kbd, mouse, console, fs, math, sysinfo):
  always `channel_send_blocking`. A dropped response corrupts the
  request/response protocol and hangs the client.
- **Init server messages** (capability delivery, spawn responses): always
  blocking. These are one-shot protocol steps that cannot be retried.

Use **non-blocking sends** (`channel_send` / `sys_chan_send`) only for
fire-and-forget event streams where dropping is acceptable:

- **Mouse/keyboard events to the window server**: the window server polls
  input; a dropped event is equivalent to a missed sample.

Rule of thumb: if the receiver will block waiting for this message, or if
losing it silently breaks a protocol, use blocking. If it's a continuous
event stream with natural redundancy, non-blocking is fine.

## Capability Transfer Ref Counting

ANY code path that places a capability endpoint in a message's `caps[]`
array MUST call `ipc::channel_inc_ref()` (for channel caps) or
`ipc::shm_inc_ref()` (for SHM caps) before sending.

- **User-space syscall path**: handled automatically by
  `translate_cap_for_send()` in trap.rs.
- **Kernel tasks using `channel_send_blocking` directly**: caller must
  manually call `channel_inc_ref()` before the send.
- **`KernelTransport::send()`**: handles this internally.
- **`send_ok_with_cap()` in init.rs**: handles this internally.

Forgetting the inc_ref causes premature channel deactivation when the
receiver closes its copy — the same class of bug as Bug 0002.

## Kernel-internal Panic Policy

Functions that take kernel-internal IDs (endpoint IDs, SHM IDs) should
**panic** on invalid inputs rather than returning error codes. Invalid
IDs from kernel-internal calls indicate bugs, not runtime conditions.

Examples: `channel_inc_ref()`, `shm_inc_ref()`, `shm_dec_ref()` all
panic on invalid/inactive IDs.

Reserve `Result`/`Option` returns for operations where failure is a
legitimate runtime possibility (e.g., resource exhaustion, user-provided
handles).
