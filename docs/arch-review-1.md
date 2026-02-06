# Architecture Review 1 — rvOS

**Date:** 2026-02-06
**Scope:** Full codebase — kernel/, user/, lib/, vendor/rust PAL, build system
**Codebase size:** ~5,000 lines of Rust + assembly

---

## 1. Executive Summary

rvOS is a well-engineered, teaching-quality RISC-V 64-bit microkernel. The code is
clean, modular, and uses zero external crates in the kernel. Key strengths:

- **Capability-based IPC** (Fuchsia-style bidirectional channels with handle passing)
- **Interrupt-safe spinlocks** with RAII guards that save/restore SIE state
- **Strong newtypes** for physical/virtual addresses and page numbers
- **Working Rust std port** — user programs use `println!`, `Vec`, `std::fs`
- **Zero-copy wire format** (`rvos-wire`) for IPC serialization
- **Clean trap handling** with correct sscratch swap and register zeroing on sret

Top concerns:

- `mem::forget(PageTable)` used at 10 sites to prevent Drop freeing page table frames
- Fixed-size resource tables throughout (64 procs, 32 channels, 16 handles/proc)
- No message queue backpressure — kernel heap can be exhausted by a malicious sender
- Duplicated syscall wrappers in `user/fs` and `user/shell` instead of using `lib/rvos`
- Copy-paste handler functions in `init.rs` for each service type
- User programs `.incbin`'d into kernel binary — no dynamic loading

---

## 2. Cursed / Janky / Hacky

| Finding | Location | Severity |
|---------|----------|----------|
| `mem::forget(PageTable)` to prevent Drop freeing page table frames — used every time a user page table is created or modified via syscall (10 call sites) | `task/process.rs:132,180` `arch/trap.rs:462,472,526,535,580,605` `arch/paging.rs:70` `task/scheduler.rs:372` | Medium |
| `UnsafeCell<Option<Filesystem>>` + `unsafe impl Sync` to get `&'static mut` access to the global filesystem | `user/fs/src/main.rs:471-474` | Medium |
| Hard-coded RAM layout (0x8000_0000 – 0x8800_0000, 128 MiB) baked into constants | `mm/frame.rs:4-6` | Low |
| Unused `_control_ep` variable (leading underscore suppresses warning) | `services/init.rs:173` | Low |
| Manual `starts_with()` reimplemented instead of using `[u8]::starts_with()` | `services/init.rs:269-274` | Low |
| Target JSON contains absolute path to linker script (`/home/ubuntu/src/temp2/rvos/user/user.ld`) — not portable | `user/riscv64gc-unknown-rvos.json` | Low |

### Why `mem::forget` is concerning

`PageTable::drop()` frees intermediate page table frames. User page tables are long-lived
and their frames are managed by the frame allocator, so every call site that creates or
borrows a `PageTable` wrapper must call `mem::forget()` to prevent the destructor from
running. This is correct but fragile — adding a new code path that forgets to call
`mem::forget` will silently corrupt the page tables. A better design would be an explicit
`PageTable::free()` method with a no-op `Drop`.

---

## 3. Generalization Concerns

What breaks as the system grows:

### Fixed-size tables

| Resource | Limit | Location |
|----------|-------|----------|
| Processes | `MAX_PROCS = 64` | `task/process.rs:13` |
| Channels | `MAX_CHANNELS = 32` | `ipc/mod.rs:9` |
| SHM Regions | `MAX_SHM_REGIONS = 32` | `ipc/mod.rs:11` |
| Handles per process | `MAX_HANDLES = 16` | `task/process.rs:14` |
| Mmap regions per process | `MAX_MMAP_REGIONS = 32` | `task/process.rs:15` |
| Boot registrations | `MAX_BOOT_REGS = 8` | `services/init.rs:23` |
| Services | `MAX_SERVICES = 4` | `services/init.rs:24` |

All use `Option<T>` arrays with linear scan. Exceeding any limit silently fails (returns
`None` or `NO_CAP`). There is no dynamic growth path.

### Other scaling issues

- **Init server hard-codes service names**: `"stdio"`, `"sysinfo"`, `"math"`, `"fs"` —
  adding a 5th service requires kernel recompilation and bumping `MAX_SERVICES`.

- **Sequential service loops**: The fs server (and sysinfo, math) serve one client at a
  time. No multiplexing, no `select()`-like primitive. If one client stalls, all others
  block.

- **Frame allocator O(n) scan**: Bitmap linear search (`frame.rs:55-64,81-98`). Becomes
  slow with high fragmentation or few free frames.

- **Message queue unbounded**: `VecDeque<Message>` per channel endpoint, no depth limit,
  no backpressure. A malicious sender can exhaust the kernel heap.

- **Allocator in std PAL**: One `mmap` syscall per allocation, no pooling. Every `Vec`
  push that triggers growth = syscall + page allocation.

- **64-byte message limit**: File I/O chunked to 61-byte data payloads (3 bytes header),
  many round-trips for large reads/writes.

- **User programs `.incbin`'d into kernel**: Adding a program requires editing
  `user_programs.S` and the Makefile. No filesystem-based loading.

- **Init service polling has a race**: Messages arriving between the poll loop and
  `channel_set_blocked()` calls can be missed. Works because services resend, but fragile.

---

## 4. Abstraction Quality

### Good abstractions

- **SpinLock with interrupt-safe RAII guard** (`sync/spinlock.rs`): Saves/restores
  interrupt state, prevents deadlock from timer firing inside critical section. Nested
  locking works correctly (innermost unlock restores state).

- **Address newtypes** (`mm/address.rs`): `PhysAddr`, `VirtAddr`, `PhysPageNum`,
  `VirtPageNum` with conversions. Prevents mixing physical and virtual addresses.

- **Capability encoding** (`ipc/mod.rs:16-26`): Tag bits in upper 2 bits distinguish
  channel vs SHM-RW vs SHM-RO capabilities. Clean encode/decode functions.

- **rvos-wire zero-copy Reader/Writer** (`lib/rvos-wire`): `read_str()` and
  `read_bytes()` return borrows into the original buffer, not copies. 20 unit tests.

- **Channel RAII in lib/rvos** (`lib/rvos/src/channel.rs`): `Drop` closes the handle,
  preventing leaks in user programs.

- **Service discovery** (`lib/rvos/src/service.rs`): Clean
  `connect_to_service("name")` pattern via boot channel.

### Bad abstractions

- **Duplicated syscall wrappers**: `user/fs/src/syscall.rs` and
  `user/shell/src/syscall.rs` each independently define `Message`, `syscall0`, `syscall1`,
  `syscall2`, and channel operations — instead of depending on `lib/rvos`. The fs server
  avoids `lib/rvos` because it doesn't link std, but the syscall layer in `lib/rvos/src/raw.rs`
  is `#![no_std]`-compatible and could be used directly.

- **Copy-paste handlers in init.rs**: `handle_sysinfo_request` (lines 168-195),
  `handle_math_request` (lines 213-235), and `handle_fs_request` (lines 245-267) are
  near-identical. Each has its own `AtomicUsize` + load/check + `channel_create_pair` +
  send-to-control + send-response pattern. Should be a single generic function
  parameterized by the service's control endpoint.

### Questionable

- **Handles are raw `usize` everywhere**: No newtype like `Handle(usize)` for type
  safety. Easy to accidentally pass a PID where a handle is expected, or vice versa.

---

## 5. Idiomatic Rust Assessment

### Good

- `#[repr(C)]` for all hardware/ABI structs (TrapFrame, PTE, Message)
- RAII patterns throughout: `SpinLockGuard`, `Channel::drop`, frame zeroing on alloc
- `const { None }` generic array init for fixed-size Option arrays
- Proper `From`/`Into` trait implementations for address types
- Builder pattern for messages (`Message::build()`)
- `SysError` enum with proper error type in lib/rvos

### Not idiomatic

- `for i in 0..count` with index instead of iterators in several places (init.rs
  endpoint polling, process.rs handle allocation). Could use
  `.iter().enumerate().find()` patterns.

- Manual `starts_with()` function in `init.rs:269-274` when `[u8]::starts_with()`
  exists in core.

- `if !handled { }` empty block in fs server main loop (dead code path).

- `Option<T>` arrays + linear scan instead of more ergonomic patterns. Acceptable for
  OS code where `alloc` may not be available, but the kernel does have a heap allocator.

### Acceptable for OS code

Heavy use of `unsafe` in inline asm, page table manipulation, MMIO device access, and
`mem::forget`. Each usage is justified by the domain — OS kernels inherently require
unsafe operations at hardware boundaries. The unsafe surface area is well-contained in
`arch/`, `mm/`, and `drivers/`.

---

## 6. Comments & Documentation Sync

### No stale comments found

Comments match implementation throughout the codebase. The code is well-commented in
critical sections.

### No TODO/FIXME/HACK/XXX

Grep across all kernel source returns zero matches. Either the code is considered
complete for its current scope, or debt is tracked externally.

### Well-commented sections

- **trap.S**: Detailed explanation of sscratch swap, U/S mode distinction, and kernel
  stack identity mapping (lines 4-116).
- **scheduler.rs**: Documents the interrupt-disable-before-drop pattern that prevents
  the scheduling race condition (lines 293-298).
- **Exit path** (`scheduler.rs:329-333`): Explains the deadlock prevention strategy
  (snapshot handles, release lock, then close).
- **IPC capability encoding** (`ipc/mod.rs:16-26`): Clear comments on tag bit layout.

### Minor inaccuracies

- `frame.rs` `first_free` comment says "first frame index available" but actually means
  "index of first frame above the kernel image" — it never moves backward once set.

- `validate_user_buffer` comment says "contiguous pages" but means "contiguous in
  physical memory" — a VA-contiguous buffer spanning non-contiguous physical pages will
  be rejected.

### README.md

Accurate and comprehensive. Process table matches actual code. Build instructions work.

---

## 7. Security Analysis

### Kernel isolation is solid

- **Page table enforcement**: User pages have U-bit set; kernel pages do not. Hardware
  prevents user code from accessing kernel memory.

- **User pointer validation**: All user pointers go through `validate_user_buffer()`
  (`trap.rs:611-643`) which walks the user page table to verify mapping exists and
  pages are physically contiguous.

- **Register zeroing on sret**: All general-purpose registers cleared before returning
  to user mode. No kernel data leakage through registers.

- **Capability-based access**: Processes can only use handles they created or received
  via IPC. No global resource directories.

- **Clean exit path**: `exit_current_from_syscall()` closes all handles and unmaps all
  regions, waking blocked peers with an EOF signal.

### Concerns

- **Message queue flooding**: No per-channel depth limit. A malicious process can send
  unlimited messages to exhaust the kernel heap, causing a panic. This is the most
  significant security gap.

- **No capability revocation**: Once a process receives a handle, it keeps it forever.
  There is no mechanism to revoke access to a channel or SHM region without closing the
  entire channel.

- **fs server trusts all clients equally**: No access control — any process that
  connects to the fs service can read, write, or delete any file. The fs server has no
  concept of ownership or permissions.

- **Handle exhaustion is silent**: When the 16-handle table fills, `alloc_handle()`
  returns `None` and the syscall returns `NO_CAP` (`usize::MAX`). User programs that
  don't check for this will silently operate on invalid handles.

- **Endpoint leak in fs server** (`user/fs/src/main.rs:869-871`): `client_file_handle`
  is not closed after `Open`, leaking a handle slot. After ~14 opens, the handle table
  fills and no more files can be opened. The code acknowledges this in a comment.

- **No ASLR**: User code and stack are identity-mapped at their physical addresses. A
  process can predict its own memory layout.

---

## 8. Debuggability

### Present

- **Panic handler** (`panic.rs`): Dumps scause, stval, sepc, sstatus on kernel panic.
- **Boot logging**: `println!` at each boot phase in `kmain`.
- **Trap logging**: Unhandled exceptions print scause, stval, sepc, sstatus, and fault
  type.
- **Validation logging**: `validate_user_buffer()` logs failed translations with PID,
  pointer, and length.
- **GDB support**: `make debug` target with QEMU GDB stub.

### Missing

- **No stack traces on panic**: Only CSR values are dumped, not the call stack. Adding
  frame pointer unwinding would significantly improve crash debugging.

- **No runtime process inspector**: Can't query process state, handle tables, or page
  table entries at runtime. A `/proc`-like introspection mechanism or kernel debugger
  command would help.

- **No IPC tracing**: Can't see which processes are blocked on which channels, or trace
  message flow between services. Would need a lightweight tracing infrastructure.

- **No memory usage reporting**: No way to query how many frames are allocated, free,
  or fragmented. The frame allocator bitmap is not exposed.

- **No per-process resource accounting**: Can't see how many handles, mmap regions, or
  channels a process is using.

---

## 9. Recommended Actions

Ordered by impact:

1. **Close leaked `client_file_handle` in fs server's `do_open()`**
   (`user/fs/src/main.rs:869`). Currently limits the system to ~14 file opens before
   the handle table fills.

2. **Add per-channel message queue depth limits** (`ipc/mod.rs`). Return an error
   (e.g., `EAGAIN`) when the queue exceeds a configurable maximum. This is the top
   security concern.

3. **Port `user/fs` to use `lib/rvos` crate** instead of duplicated syscall wrappers.
   The raw syscall layer in `lib/rvos/src/raw.rs` is `#![no_std]`-compatible.

4. **Deduplicate `init.rs` handler functions** into a single generic
   `handle_service_request(service_ep: &AtomicUsize, boot_ep_b: usize)`.

5. **Replace `mem::forget(PageTable)` pattern** with an explicit `PageTable::into_raw()`
   that consumes the wrapper without running Drop, or make Drop a no-op and add an
   explicit `free()` method.

6. **Add `Handle(usize)` newtype** for type safety in process handle tables and syscall
   interfaces.

7. **Replace hard-coded RAM constants** with device tree (DTB) parsing at boot.

8. **Validate `.incbin` file existence in `kernel/build.rs`** — the current parser does
   simple string matching on `.incbin` directives but doesn't check that the referenced
   files exist, leading to confusing linker errors.

---

## 10. Build System Notes

### Smart decisions

- **build-std flags in Makefile, not `.cargo/config.toml`**: Prevents cargo config from
  leaking into `x.py` bootstrap builds. This was a hard-won lesson.

- **`build.rs` auto-parses `.incbin` paths**: The kernel build script reads
  `user_programs.S` and emits `cargo:rerun-if-changed` for each referenced binary.
  User program changes automatically trigger kernel rebuild.

- **Correct build ordering**: `make build` compiles user programs first, then kernel,
  because the kernel `.incbin`'s the user binaries.

- **Toolchain isolation**: `rustup toolchain link rvos` points to the custom stage1
  compiler; user programs built with `cargo +rvos` use the rvOS sysroot.

### Fragile points

- **`.incbin` path parser is simple string matching**: No existence check on the
  referenced files. If a path is wrong, the error surfaces as a confusing assembler or
  linker failure.

- **Target JSON has absolute path**: `riscv64gc-unknown-rvos.json` contains
  `-T/home/ubuntu/src/temp2/rvos/user/user.ld` in pre-link args. Not portable to other
  machines or directory layouts.

- **`cargo +rvos clean` required after `build-std-lib`**: Stale rlib hash mismatches
  cause cryptic linking errors. This is a footgun for anyone modifying the std library.

- **`BOOTSTRAP_SKIP_TARGET_SANITY=1` required for x.py**: The custom target doesn't
  pass x.py's built-in sanity checks, so the env var is mandatory. Easy to forget.
