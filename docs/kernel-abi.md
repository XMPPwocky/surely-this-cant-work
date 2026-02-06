# rvOS Kernel ABI Reference

This document describes the system call interface, IPC message format, handle
table layout, and boot protocol for rvOS user-mode processes.

---

## 1. Calling Convention

rvOS uses the standard RISC-V `ecall` instruction to transition from U-mode
(user) to S-mode (supervisor/kernel).

| Role               | Register | Notes                                     |
|--------------------|----------|-------------------------------------------|
| Syscall number     | `a7`     | Identifies which syscall to invoke        |
| Argument 0         | `a0`     | First argument (also receives return 0)   |
| Argument 1         | `a1`     | Second argument (also receives return 1)  |
| Return value 0     | `a0`     | Primary return value                      |
| Return value 1     | `a1`     | Secondary return value (some syscalls)    |

**Sequence:**

1. The user program places the syscall number in `a7` and arguments in `a0`/`a1`.
2. The user program executes `ecall`.
3. The kernel trap handler saves the full register file into a `TrapFrame`,
   advances `sepc` by 4 (past the `ecall` instruction), dispatches based on
   `a7`, and writes return values back into the trap frame's `a0`/`a1` slots.
4. On return to user mode, the caller reads results from `a0` (and `a1` where
   applicable).

**Error convention:** Most syscalls return `0` on success. A return value of
`usize::MAX` (`0xFFFF_FFFF_FFFF_FFFF` on RV64) indicates an error (invalid
handle, bad pointer, allocation failure, etc.). The non-blocking receive
(`SYS_CHAN_RECV`) returns `1` when no message is available, distinguishing
"empty" from "error".

### User-Side Wrapper Patterns

The user-side syscall wrappers (see `lib/rvos/src/raw.rs`) use inline
assembly with three patterns:

```rust
// Zero-argument syscall (a0 set to 0, result in a0)
fn syscall0(num: usize) -> usize;

// One-argument syscall (a0 = arg, result in a0)
fn syscall1(num: usize, a0: usize) -> usize;

// Two-argument syscall (a0 = arg0, a1 = arg1, results in a0 and a1)
fn syscall2(num: usize, a0: usize, a1: usize) -> (usize, usize);
```

All wrappers use `options(nostack)` since no stack manipulation is needed.

---

## 2. Syscall Table

| Number | Name                  | Args                          | Returns                    | Description                                                |
|--------|-----------------------|-------------------------------|----------------------------|------------------------------------------------------------|
| 93     | `SYS_EXIT`            | `a0` = exit code (unused)     | Does not return            | Terminates the calling process.                            |
| 124    | `SYS_YIELD`           | (none)                        | `a0` = 0                  | Voluntarily yields the CPU to the scheduler.               |
| 172    | `SYS_GETPID`          | (none)                        | `a0` = PID                | Returns the calling process's PID.                         |
| 200    | `SYS_CHAN_CREATE`      | (none)                        | `a0` = handle_a, `a1` = handle_b | Creates a bidirectional channel pair. Returns two handles. |
| 201    | `SYS_CHAN_SEND`        | `a0` = handle, `a1` = msg_ptr | `a0` = 0, 5, or `usize::MAX` | Sends a message on a channel. Non-blocking. 0=success, 5=queue full, MAX=error. |
| 202    | `SYS_CHAN_RECV`        | `a0` = handle, `a1` = msg_ptr | `a0` = 0, 1, or `usize::MAX` | Non-blocking receive. 0=success, 1=empty, MAX=error.    |
| 203    | `SYS_CHAN_CLOSE`       | `a0` = handle                 | `a0` = 0 or `usize::MAX`  | Closes a channel handle. Decrements the endpoint's ref count; deactivates only when the last handle is closed. |
| 204    | `SYS_CHAN_RECV_BLOCKING` | `a0` = handle, `a1` = msg_ptr | `a0` = 0 or `usize::MAX` | Blocking receive. Suspends the process until a message arrives. |
| 222    | `SYS_MMAP`            | `a0` = hint (ignored), `a1` = length | `a0` = address or `usize::MAX` | Allocates zeroed pages and maps them into the process. |
| 215    | `SYS_MUNMAP`          | `a0` = address, `a1` = length | `a0` = 0 or `usize::MAX`  | Unmaps and frees previously mmap'd pages.                  |

### Detailed Syscall Descriptions

#### SYS_EXIT (93)

Terminates the current process. The exit code in `a0` is currently logged but
not otherwise used. The process is moved to `Dead` state and removed from the
scheduler ready queue. Does not return.

#### SYS_YIELD (124)

Invokes `schedule()` to yield the CPU. The calling process is moved to the
back of the ready queue. Always returns 0.

#### SYS_GETPID (172)

Returns the PID of the calling process in `a0`. PIDs are assigned sequentially
starting from 1 (PID 0 is the idle task).

#### SYS_CHAN_CREATE (200)

Creates a new bidirectional channel (Fuchsia-style). Allocates a channel with
two endpoints (A and B), installs both endpoints as handles in the calling
process's handle table, and returns the handle indices:

- `a0` = handle for endpoint A
- `a1` = handle for endpoint B

The two handles can be used independently. A common pattern is to keep one
handle and pass the other to another process via a message capability.

#### SYS_CHAN_SEND (201)

Sends a message on the channel identified by `handle` (`a0`). The `msg_ptr`
(`a1`) must point to a valid `Message` struct in user memory.

The kernel:
1. Translates the user VA to a PA by walking the process page table.
2. Looks up `handle` in the process's handle table to get the global endpoint ID.
3. Reads the `Message` from user memory.
4. Overwrites `msg.sender_pid` with the calling process's actual PID (cannot be forged).
5. If `msg.cap != NO_CAP`, translates the capability handle from a local handle to a global endpoint ID.
6. Checks that the destination queue has not reached `MAX_QUEUE_DEPTH` (64).
7. Enqueues the message on the peer's receive queue.
8. If the peer was blocked on a receive, wakes it.

Returns:
- `0` -- success.
- `5` -- queue full (`QUEUE_FULL`). The destination endpoint's message queue has
  reached `MAX_QUEUE_DEPTH`. The message was **not** enqueued. The caller should
  retry later or implement backpressure.
- `usize::MAX` -- error (invalid handle, invalid pointer, invalid cap handle,
  closed channel).

#### SYS_CHAN_RECV (202)

Non-blocking receive. Attempts to dequeue a message from the channel identified
by `handle` (`a0`) and writes it to the `Message` buffer at `msg_ptr` (`a1`).

If a received message carries a capability (`cap != NO_CAP`), the kernel
automatically installs the global endpoint ID into the receiver's handle table
and rewrites `msg.cap` to the new local handle index.

Returns:
- `0` -- message received and written to buffer.
- `1` -- no message available (queue empty).
- `usize::MAX` -- error (invalid handle or pointer).

#### SYS_CHAN_RECV_BLOCKING (204)

Blocking receive. Behaves like `SYS_CHAN_RECV` but suspends the calling process
if no message is available:

1. Try to dequeue a message.
2. If empty, record this PID as "blocked" on the endpoint, move the process to
   `Blocked` state, and invoke `schedule()`.
3. When a message is sent to this endpoint, the sender's `channel_send` detects
   the blocked PID and calls `wake_process()`, moving it back to `Ready`.
4. The awakened process loops back and re-attempts the receive.

Returns 0 on success, `usize::MAX` on error.

#### SYS_CHAN_CLOSE (203)

Closes the channel handle. The local handle slot is freed in the process's
handle table. The endpoint's reference count is decremented. If the ref count
reaches 0, the channel is deactivated and any blocked peer is woken. If both
endpoints' ref counts are 0, the channel slot is freed entirely.

This means `SYS_CHAN_CLOSE` is safe to call after transferring a capability
via IPC: the sender can close its local handle and the channel stays alive as
long as the receiver (or any other holder) still has a reference.

When a channel capability is sent via `SYS_CHAN_SEND`, the kernel increments
the endpoint's ref count before enqueuing. When the receiver installs the
capability as a handle, no additional increment is needed. When the receiver
eventually closes that handle via `SYS_CHAN_CLOSE`, the ref count is
decremented back.

Returns 0 on success, `usize::MAX` if the handle is invalid.

#### SYS_MMAP (222)

Allocates contiguous physical pages, zeroes them, and maps them into the
calling process's user page table with U+R+W permissions.

- `a0` = hint address (currently ignored).
- `a1` = length in bytes (rounded up to page granularity).

Because rvOS uses identity mapping (VA == PA), the returned address is both the
virtual and physical address of the allocation. The region is recorded in the
process's `mmap_regions` table (max 32 regions). A TLB flush (`sfence.vma`) is
performed after mapping.

Returns the base address on success, `usize::MAX` on failure (zero length,
allocation failure, not a user process, region table full).

#### SYS_MUNMAP (215)

Unmaps and frees previously mmap'd pages.

- `a0` = base address (must be page-aligned).
- `a1` = length in bytes (rounded up to page granularity).

The kernel validates that the region matches a previously recorded mmap, removes
the page table entries, frees the physical frames, and flushes the TLB.

Returns 0 on success, `usize::MAX` on error (unaligned address, zero length,
region not found).

---

## 3. Message Struct

The `Message` struct is the fundamental IPC data unit, shared between kernel
and user space. It is `#[repr(C)]` to guarantee a stable ABI layout.

### Definition

```rust
#[repr(C)]
pub struct Message {
    pub data: [u8; 64],     // offset 0x00, 64 bytes of payload
    pub len: usize,         // offset 0x40, number of valid bytes in data
    pub sender_pid: usize,  // offset 0x48, PID of sender (set by kernel)
    pub cap: usize,         // offset 0x50, capability (handle or NO_CAP)
}
```

### Field Layout (RV64, 8-byte usize)

| Field        | Offset | Size    | Description                                            |
|--------------|--------|---------|--------------------------------------------------------|
| `data`       | 0x00   | 64 bytes | Message payload. Only `data[0..len]` is meaningful.   |
| `len`        | 0x40   | 8 bytes  | Number of valid payload bytes (0..64).                |
| `sender_pid` | 0x48   | 8 bytes  | PID of the sender. The kernel overwrites this field on send; user-set values are ignored. |
| `cap`        | 0x50   | 8 bytes  | Capability slot. `NO_CAP` (usize::MAX) means no capability attached. Otherwise, a handle index. |

**Total size:** 88 bytes (0x58).

### Constants

- `MAX_MSG_SIZE` = 64 -- maximum payload size in bytes.
- `NO_CAP` = `usize::MAX` (`0xFFFF_FFFF_FFFF_FFFF`) -- sentinel meaning "no capability attached."

### Capability Translation

The `cap` field undergoes translation during send and receive:

- **On send:** If `cap != NO_CAP`, the kernel interprets it as a *local handle*
  in the sender's handle table, looks up the corresponding global endpoint ID,
  and replaces `cap` with that global ID before enqueuing.
- **On receive:** If the dequeued message has `cap != NO_CAP`, the kernel
  installs the global endpoint ID into the *receiver's* handle table, allocating
  a new local handle, and replaces `cap` with that local handle index before
  writing the message to user memory.

This means user code always sees and sets `cap` as a local handle index -- the
kernel transparently manages the global-to-local mapping.

---

## 4. Handle Table

Each process has a fixed-size handle table that maps local handle indices to
global IPC endpoint IDs.

```rust
pub const MAX_HANDLES: usize = 32;

pub struct Process {
    // ...
    pub handles: [Option<HandleObject>; MAX_HANDLES],
    // ...
}
```

### Properties

- **Size:** 32 slots, indexed 0..31.
- **Slot contents:** `None` = free, `Some(global_endpoint_id)` = occupied.
- **Allocation:** Linear scan for the first `None` slot. Panics if the table is full.
- **Lookup:** `handles[local_handle]` returns `Some(global_endpoint_id)` or `None`.
- **Free:** Sets `handles[local_handle] = None`.

### Handle 0 Convention

By convention, **handle 0 is the boot channel** -- the process's connection to
the init server. When the kernel spawns a user process via
`spawn_user_with_boot_channel()` or `spawn_user_elf_with_boot_channel()`, it
pre-sets `handles[0] = Some(boot_ep)` before the process starts executing.

User processes use handle 0 to send service discovery requests to the init
server (see Boot Protocol below).

### Handle Lifecycle

1. **Creation:** `SYS_CHAN_CREATE` allocates two handles (for endpoints A and B).
2. **Transfer:** Sending a message with `cap` set to a local handle transfers
   the underlying endpoint to the receiver (the receiver gets a new handle via
   capability translation). The kernel increments the endpoint's ref count on
   send, so the sender can safely call `SYS_CHAN_CLOSE` afterward without
   deactivating the channel.
3. **Closure:** `SYS_CHAN_CLOSE` frees the local handle slot and decrements the
   endpoint's ref count. The channel is only deactivated when the last handle
   to an endpoint is closed.

---

## 5. IPC Channels

rvOS uses Fuchsia-style bidirectional channels as its sole IPC primitive. There
are no pipes, shared memory regions, or signals -- all inter-process
communication goes through channels.

### Channel Structure

Each channel has two endpoints (A and B) and two message queues:

```
          queue_a (messages for A to recv)
Endpoint A <=========================> Endpoint B
          queue_b (messages for B to recv)
```

- `send(ep_a)` enqueues into `queue_b` (delivered to B's receive).
- `send(ep_b)` enqueues into `queue_a` (delivered to A's receive).
- `recv(ep_a)` dequeues from `queue_a`.
- `recv(ep_b)` dequeues from `queue_b`.

### Global Endpoint IDs

Internally, endpoints are identified by global IDs:

- Channel index `i` has endpoints `2*i` (side A) and `2*i + 1` (side B).
- User code never sees global IDs -- it uses local handle indices that the
  kernel translates on every syscall.

### Channel Limits

- `MAX_CHANNELS` = 64 -- maximum number of simultaneous channels.
- `MAX_QUEUE_DEPTH` = 64 -- maximum number of messages queued per endpoint.
  When a send would exceed this limit, `SYS_CHAN_SEND` returns error code 5
  (`QUEUE_FULL`) and the message is not enqueued.

### Blocking Semantics

Each endpoint can have at most one blocked PID (`blocked_a` / `blocked_b`).
When a process calls `SYS_CHAN_RECV_BLOCKING` on an empty queue, it records
itself as blocked on that endpoint. When a sender enqueues a message, it
checks for a blocked PID and wakes that process.

### Channel Closure

Each endpoint has a reference count. When all handles to an endpoint are
closed (ref count reaches 0), the channel is deactivated. After deactivation,
sends return an error and no new messages can be delivered. Messages already
in the queue can still be drained. When both endpoints' ref counts reach 0,
the channel slot is freed for reuse.

---

## 6. Capability Passing

Capabilities in rvOS are channel endpoints. A process can pass a channel
endpoint to another process by setting the `cap` field of a `Message` to a
local handle index before sending.

### Mechanism

1. **Sender** sets `msg.cap = local_handle` (a handle in its own table).
2. **Kernel (send path)** translates `local_handle` to a global endpoint ID.
3. **Kernel (recv path)** installs the global endpoint ID as a new handle in
   the receiver's table and rewrites `msg.cap` to the receiver's new local
   handle.
4. **Receiver** reads `msg.cap` to obtain a local handle for the transferred
   endpoint.

This is how the init server passes newly created service channels to clients:
it creates a channel pair, sends one endpoint to the service server (via the
control channel), and sends the other endpoint to the requesting client (via
the boot channel), both as capabilities.

### No Capability

Set `msg.cap = NO_CAP` (usize::MAX) when no capability transfer is intended.
This is the default in `Message::new()`.

---

## 7. Memory Model

### Identity Mapping

rvOS uses Sv39 (3-level, 39-bit virtual address) page tables. All memory --
kernel and user -- is identity-mapped, meaning VA == PA for all mapped
addresses. This simplifies DMA (VirtIO GPU needs physical addresses), buffer
access across privilege levels, and mmap return values.

### Page Size

- `PAGE_SIZE` = 4096 bytes (4 KiB).
- `PAGE_SIZE_BITS` = 12.

### User Page Table Layout

Each user process gets its own page table (referenced by `user_satp`).
The table maps:

| Region                  | Permissions  | Notes                                  |
|-------------------------|-------------|----------------------------------------|
| Kernel text             | R+X         | No U bit -- not accessible from U-mode |
| Kernel rodata           | R           | No U bit                               |
| Kernel data/bss/stack   | R+W         | No U bit                               |
| Free memory             | R+W         | No U bit (excludes user pages)         |
| UART (0x1000_0000)      | R+W         | No U bit                               |
| PLIC (0x0C00_0000)      | R+W         | No U bit                               |
| CLINT (0x0200_0000)     | R+W         | No U bit                               |
| VirtIO (0x1000_1000)    | R+W         | No U bit                               |
| User code pages         | U+R+W+X     | Identity-mapped at PA                  |
| User stack pages        | U+R+W       | Identity-mapped at PA                  |
| mmap'd pages            | U+R+W       | Identity-mapped at PA, zeroed          |

### User Stack

- `USER_STACK_PAGES` = 8 (32 KiB).
- The stack grows downward from `user_stack_top`.

### Kernel Stack (per process)

- `KERNEL_STACK_PAGES` = 4 (16 KiB).
- Each process (including user processes) has a dedicated kernel stack used
  during trap handling.

### mmap Tracking

Each process can track up to `MAX_MMAP_REGIONS` = 32 mmap'd regions. Each
region records `base_ppn` and `page_count`. The `SYS_MUNMAP` syscall
validates that the requested unmap matches a tracked region before freeing.

---

## 8. Boot Protocol

When a user process is spawned, the kernel provides it with a single
communication channel -- the **boot channel** -- pre-installed as handle 0.
The other end of this channel is held by the **init server**, a kernel task
that acts as a service directory.

### Startup Sequence

1. The kernel calls `ipc::channel_create_pair()` to create a channel with
   endpoints (ep_a, ep_b).
2. ep_a is installed as handle 0 in the new user process
   (`proc.handles[0] = Some(ep_a)`).
3. ep_b is registered with the init server via `init::register_boot(ep_b, console_type)`.
4. The user process is spawned. When it starts executing, handle 0 is ready
   for use.

### Service Discovery Protocol

To obtain a service, the user process sends a request message on handle 0 (the
boot channel) and waits for a response:

```
User Process                          Init Server
    |                                      |
    |-- send(handle=0, data="stdio") ----->|
    |                                      |  (creates channel pair)
    |                                      |  (sends server_ep to console server)
    |<-- recv(handle=0) ------------------|
    |    data="ok", cap=<stdio_handle>     |
    |                                      |
    (use stdio_handle for I/O)
```

**Request format:**
- `msg.data` contains the service name as ASCII bytes.
- `msg.len` is the length of the service name.
- `msg.cap` = `NO_CAP` (no capability needed in the request).

**Response format:**
- `msg.data[0..msg.len]` = `"ok"` on success, `"unknown"` if the service is not recognized.
- `msg.cap` = local handle for the new service channel (on success).

### Available Services

| Service Name | Description                                                        |
|--------------|--------------------------------------------------------------------|
| `"stdio"`    | Console I/O. Returns a channel connected to the appropriate console server (serial or framebuffer, depending on how the process was spawned). |
| `"sysinfo"`  | System information. Returns a channel connected to the sysinfo service. Send `"PS"` to get a process list (multi-message response terminated by a zero-length sentinel). |
| `"math"`     | Math computation service. Returns a channel connected to the math service. Send serialized `MathOp` messages; receive `MathResponse` messages (uses the `rvos_wire` serialization format). |
| `"fs"`       | Filesystem service. Returns a control channel to the tmpfs server. Send Open/Delete/Stat/Readdir requests; Open returns a file channel capability for Read/Write operations. |

### Service Channel Lifecycle

Service channels are ephemeral. The typical pattern is:

1. Send a service name on handle 0 to request a channel.
2. Receive the response; extract the service handle from `msg.cap`.
3. Use the service handle for requests/responses.
4. Close the service handle with `SYS_CHAN_CLOSE` when done.

The boot channel (handle 0) remains open for the process's entire lifetime
and can be reused for multiple service requests.

### Console I/O Protocol

Once a `"stdio"` channel is obtained, I/O uses the `Message` struct directly:

- **Write:** Set `msg.data` to the bytes to output and `msg.len` to the byte
  count (max 64 bytes per message). Send via `SYS_CHAN_SEND`. For strings
  longer than 64 bytes, send multiple messages.
- **Read:** Call `SYS_CHAN_RECV_BLOCKING` on the stdio handle. The console
  server sends one message per input line, with the line contents (including
  trailing newline) in `msg.data[0..msg.len]`.

### Sysinfo Protocol

After obtaining a `"sysinfo"` channel:

1. Send a message with `data = "PS"`, `len = 2`.
2. Receive messages in a loop via `SYS_CHAN_RECV_BLOCKING`. Each message
   contains a chunk of the process list as text.
3. A message with `len = 0` is the sentinel indicating the end of the response.
4. Close the sysinfo handle.

---

## 9. Process States

| State     | Description                                                  |
|-----------|--------------------------------------------------------------|
| `Ready`   | Eligible for scheduling; in the ready queue.                 |
| `Running` | Currently executing on the CPU.                              |
| `Blocked` | Waiting for an event (e.g., blocking channel receive). Not in the ready queue. |
| `Dead`    | Terminated via `SYS_EXIT`. Will be cleaned up.               |

### State Transitions

```
        spawn
          |
          v
       Ready <-------+
          |           |
    schedule()        | wake_process()
          |           |
          v           |
       Running -----> Blocked
          |              (SYS_CHAN_RECV_BLOCKING on empty queue)
          |
     SYS_EXIT
          |
          v
        Dead
```

---

## 10. Limits Summary

| Constant            | Value | Description                         |
|---------------------|-------|-------------------------------------|
| `MAX_HANDLES`       | 32    | Handle table slots per process      |
| `MAX_PROCS`         | 64    | Maximum number of processes         |
| `MAX_CHANNELS`      | 64    | Maximum simultaneous channels       |
| `MAX_QUEUE_DEPTH`   | 64    | Maximum messages per endpoint queue  |
| `MAX_MSG_SIZE`      | 64    | Maximum message payload (bytes)     |
| `MAX_MMAP_REGIONS`  | 32    | mmap tracking slots per process     |
| `PAGE_SIZE`         | 4096  | Page size (bytes)                   |
| `KERNEL_STACK_PAGES`| 4     | Kernel stack per process (16 KiB)   |
| `USER_STACK_PAGES`  | 8     | User stack per process (32 KiB)     |
| `NO_CAP`            | usize::MAX | Sentinel for "no capability"   |
