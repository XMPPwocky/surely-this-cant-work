# Shared Memory

This document specifies the design for shared memory regions in rvOS. Shared
memory is the **second kernel object type** (alongside channels) that processes
can hold handles to.

---

## 1. Overview

Shared memory allows two or more processes to map the same physical pages into
their address spaces and communicate through direct loads and stores, avoiding
the per-message overhead of channel IPC for bulk data transfer.

### Design Principles

- Shared memory regions are **kernel objects** tracked in a global table,
  analogous to channels.
- Processes reference shared memory regions through **handles** in their
  per-process handle table -- the same table used for channel endpoints.
- Handles carry **permissions** (read-only or read-write). The kernel enforces
  permissions when mapping pages into a process's address space.
- Shared memory integrates with the existing `SYS_MMAP` syscall: when a handle
  is provided, mmap maps the shared region instead of allocating fresh pages.
- Handles are transferred between processes via IPC capability passing, just
  like channel endpoints.

---

## 2. Kernel Object: Shared Memory Region

### Internal Structure

```rust
const MAX_SHM_REGIONS: usize = 32;

struct ShmRegion {
    base_ppn: PhysPageNum,   // first physical page of the region
    page_count: usize,       // number of contiguous physical pages
    ref_count: usize,        // number of outstanding handles (RO + RW)
    active: bool,            // false after all handles closed and all mappings removed
}
```

### Global Table

Shared memory regions are stored in a global table protected by a `SpinLock`,
mirroring the channel manager pattern:

```rust
static SHM_REGIONS: SpinLock<ShmManager> = SpinLock::new(ShmManager::new());
```

Each region is identified by a **global SHM ID** (its index in the table).
User code never sees global IDs -- it uses local handle indices that the kernel
translates on every syscall.

### Limits

| Constant            | Value | Description                              |
|---------------------|-------|------------------------------------------|
| `MAX_SHM_REGIONS`   | 32    | Maximum simultaneous shared memory regions |

---

## 3. Handle Table Changes

### Current Design (Channels Only)

```rust
pub handles: [Option<usize>; MAX_HANDLES],
// slot value = global channel endpoint ID
```

### New Design (Channels + Shared Memory)

The handle table must distinguish between channel endpoints and shared memory
regions. Each slot stores a tagged value:

```rust
#[derive(Clone, Copy)]
pub enum HandleObject {
    Channel(usize),             // global endpoint ID
    Shm { id: usize, rw: bool }, // global SHM ID + permission flag
}

pub handles: [Option<HandleObject>; MAX_HANDLES],
```

- `HandleObject::Channel(ep_id)` -- a channel endpoint (existing behavior).
- `HandleObject::Shm { id, rw: true }` -- a read-write shared memory handle.
- `HandleObject::Shm { id, rw: false }` -- a read-only shared memory handle.

### Backward Compatibility

All existing channel syscalls (`SYS_CHAN_SEND`, `SYS_CHAN_RECV`, etc.) check
that the handle resolves to a `HandleObject::Channel`. If it resolves to
`HandleObject::Shm`, the syscall returns `usize::MAX` (error). Likewise,
`SYS_SHM_CREATE` and the SHM-aware `SYS_MMAP` path check for `HandleObject::Shm`.

### Handle Lifecycle

1. **Creation**: `SYS_SHM_CREATE` allocates a region and installs a RW handle.
2. **Transfer**: A process sends a handle via IPC capability passing. The
   kernel translates the local handle to a `(global_shm_id, rw)` pair on send,
   and installs a new local handle in the receiver on recv. The permission bit
   (`rw`) travels with the handle.
3. **Downgrade**: A process can create a read-only duplicate of a RW handle
   and pass it to an untrusted peer (see `SYS_SHM_DUP_RO`).
4. **Closure**: `SYS_CHAN_CLOSE` works on SHM handles too -- it frees the
   local handle slot and decrements the region's `ref_count`. When `ref_count`
   reaches zero, the region's physical pages are freed.

---

## 4. Capability Passing (IPC Integration)

### Wire Format

The `Message.cap` field already carries a single capability per message. The
mechanism is extended to support both object types:

**On send (`SYS_CHAN_SEND`):**

1. The kernel reads `msg.cap` as a local handle index.
2. It looks up the handle in the sender's table.
3. If `HandleObject::Channel(ep)` -- existing behavior: replace `cap` with the
   global endpoint ID. The kernel also stores a tag bit indicating the type.
4. If `HandleObject::Shm { id, rw }` -- replace `cap` with the global SHM ID
   and the permission bit. Increment the region's `ref_count`.

**On receive (`SYS_CHAN_RECV` / `SYS_CHAN_RECV_BLOCKING`):**

1. If the message carries a capability, the kernel examines the type tag.
2. For a channel capability: existing behavior (install endpoint in receiver's
   handle table as `HandleObject::Channel`).
3. For a SHM capability: install in receiver's handle table as
   `HandleObject::Shm { id, rw }` with the transferred permission.
4. Rewrite `msg.cap` to the receiver's new local handle index.

### Internal Capability Encoding

Inside the kernel message queue (not visible to userspace), the `cap` field is
extended to encode the object type and permission:

```
Bits 63..62: type tag
  00 = no capability (NO_CAP)
  01 = channel endpoint
  10 = shared memory (RW)
  11 = shared memory (RO)
Bits 61..0:  global object ID (endpoint ID or SHM ID)
```

User code continues to see `cap` as a plain local handle index (or `NO_CAP`).
The encoding is purely internal to the kernel's message queues.

---

## 5. Syscall Interface

### New Syscalls

| Number | Name             | Args                            | Returns                   | Description                                           |
|--------|------------------|---------------------------------|---------------------------|-------------------------------------------------------|
| 205    | `SYS_SHM_CREATE` | `a0` = size (bytes)            | `a0` = handle or `usize::MAX` | Creates a shared memory region and returns a RW handle. |
| 206    | `SYS_SHM_DUP_RO` | `a0` = shm handle              | `a0` = new handle or `usize::MAX` | Duplicates a SHM handle as read-only.              |

### Modified Syscalls

| Number | Name        | Change                                                                       |
|--------|-------------|------------------------------------------------------------------------------|
| 222    | `SYS_MMAP`  | `a0` = shm handle (or 0 for anonymous), `a1` = length. If `a0` is a valid SHM handle, maps the shared region instead of allocating new pages. |
| 215    | `SYS_MUNMAP` | Unchanged for anonymous mappings. For SHM-backed mappings, unmaps pages but does NOT free the physical frames (they belong to the SHM region). |
| 203    | `SYS_CHAN_CLOSE` | Now also works for SHM handles: frees the local slot and decrements `ref_count`. |

---

## 6. Detailed Syscall Descriptions

### SYS_SHM_CREATE (205)

Creates a new shared memory region backed by contiguous zeroed physical pages.

**Registers:**

| Register | Role     | Value                               |
|----------|----------|-------------------------------------|
| `a7`     | syscall  | 205                                 |
| `a0`     | arg 0    | Size in bytes (rounded up to page granularity) |
| `a0`     | return 0 | Local handle index (RW), or `usize::MAX` on error |

**Kernel behavior:**

1. Validate: `size > 0`. If zero, return `usize::MAX`.
2. Compute `page_count = ceil(size / PAGE_SIZE)`.
3. Allocate `page_count` contiguous physical frames via `frame_alloc_contiguous()`.
   If allocation fails, return `usize::MAX`.
4. Zero the allocated pages.
5. Create a new `ShmRegion` in the global table with `ref_count = 1`.
   If the table is full, free the frames and return `usize::MAX`.
6. Install `HandleObject::Shm { id: shm_id, rw: true }` in the caller's
   handle table. If the handle table is full, clean up and return `usize::MAX`.
7. Return the local handle index.

**Error conditions:**

- `size == 0`
- Frame allocation failure (out of memory)
- SHM region table full (`MAX_SHM_REGIONS` reached)
- Handle table full (`MAX_HANDLES` reached)

### SYS_SHM_DUP_RO (206)

Creates a read-only duplicate of an existing shared memory handle. The new
handle refers to the same underlying region but only permits read-only
mappings.

**Registers:**

| Register | Role     | Value                               |
|----------|----------|-------------------------------------|
| `a7`     | syscall  | 206                                 |
| `a0`     | arg 0    | Local handle index of existing SHM handle |
| `a0`     | return 0 | New local handle index (RO), or `usize::MAX` on error |

**Kernel behavior:**

1. Look up `a0` in the caller's handle table.
2. Verify it is `HandleObject::Shm { id, .. }`. If not, return `usize::MAX`.
3. Increment the region's `ref_count`.
4. Install `HandleObject::Shm { id, rw: false }` in the caller's handle table.
5. Return the new local handle index.

**Notes:**

- Both RW and RO handles can be duplicated as RO. This is the only permission
  downgrade path -- there is no way to upgrade an RO handle to RW.
- The caller retains its original handle. The typical use is to dup-RO and
  then pass the RO handle to an untrusted peer via IPC.

### SYS_MMAP (222) -- Extended

The existing `SYS_MMAP` gains a dual mode: **anonymous** (allocate fresh pages)
and **shared** (map an existing SHM region).

**Registers:**

| Register | Role     | Value                               |
|----------|----------|-------------------------------------|
| `a7`     | syscall  | 222                                 |
| `a0`     | arg 0    | SHM handle (local index), or `0` for anonymous mapping |
| `a1`     | arg 1    | Length in bytes                      |
| `a0`     | return 0 | Mapped address, or `usize::MAX` on error |

**Mode 1: Anonymous (`a0 == 0`)**

Existing behavior, unchanged. Allocates fresh zeroed pages and maps them
U+R+W into the caller's address space.

**Mode 2: Shared (`a0 != 0`)**

1. Look up handle `a0` in the caller's handle table.
2. Verify it is `HandleObject::Shm { id, rw }`. If not, return `usize::MAX`.
3. Retrieve the `ShmRegion` from the global table.
4. Validate: `length <= region.page_count * PAGE_SIZE`. If the requested
   length exceeds the region size, return `usize::MAX`. (Partial mapping of
   a region is permitted; mapping beyond the region is not.)
5. Compute `map_pages = ceil(length / PAGE_SIZE)`.
6. Determine page table flags:
   - If `rw == true`: `PTE_R | PTE_W | PTE_U`
   - If `rw == false`: `PTE_R | PTE_U` (no write permission)
7. Map the region's physical pages into the caller's user page table at their
   identity-mapped addresses (VA == PA, as with all rvOS mappings).
8. Record the mapping in the process's `mmap_regions` table (for later munmap).
9. Flush TLB (`sfence.vma`).
10. Return the base virtual address (== base physical address).

**Error conditions (shared mode):**

- Invalid handle or handle is not SHM
- Requested length exceeds region size
- Length is zero
- Not a user process
- mmap region table full

### SYS_MUNMAP (215) -- Extended

**Registers:** Unchanged.

| Register | Role     | Value                               |
|----------|----------|-------------------------------------|
| `a7`     | syscall  | 215                                 |
| `a0`     | arg 0    | Base address (page-aligned)         |
| `a1`     | arg 1    | Length in bytes                      |
| `a0`     | return 0 | 0 on success, `usize::MAX` on error |

**Behavior change:**

The kernel must distinguish anonymous mappings from SHM-backed mappings when
unmapping:

1. Look up the region in the process's `mmap_regions` table.
2. If the region is tagged as SHM-backed:
   - Remove page table entries (PTE cleared to invalid).
   - **Do NOT** free the physical frames (they belong to the SHM region and
     may be mapped by other processes).
   - Remove the region from the process's tracking table.
   - Flush TLB.
3. If the region is anonymous (existing behavior):
   - Remove PTEs, free physical frames, remove from tracking, flush TLB.

To support this, the `MmapRegion` struct is extended:

```rust
#[derive(Clone, Copy)]
pub struct MmapRegion {
    pub base_ppn: usize,
    pub page_count: usize,
    pub shm_id: Option<usize>,  // None = anonymous, Some(id) = SHM-backed
}
```

### SYS_CHAN_CLOSE (203) -- Extended

Now accepts both channel and SHM handles.

**Behavior for SHM handles:**

1. Look up handle in the caller's table.
2. If `HandleObject::Shm { id, .. }`:
   - Free the local handle slot.
   - Decrement the region's `ref_count`.
   - If `ref_count` reaches 0 and no mappings are active, free the region's
     physical frames and mark the slot as free.
3. If `HandleObject::Channel(ep)`: existing behavior (deactivate channel).

---

## 7. Permission Model

### Handle Permissions

| Handle type  | Can mmap RW? | Can mmap RO? | Can dup as RO? | Can dup as RW? |
|-------------|-------------|-------------|---------------|---------------|
| Shm (RW)    | Yes         | Yes         | Yes           | No            |
| Shm (RO)    | No          | Yes         | Yes           | No            |

- A **RW handle** allows mapping the region with read-write page permissions.
- A **RO handle** only allows read-only mappings. Attempting to mmap a region
  through an RO handle always results in `PTE_R | PTE_U` (no `PTE_W`).
- There is no privilege escalation path: RO handles cannot be upgraded to RW.
- Duplication always produces an RO handle. The original RW handle is the
  "master" handle, created only by `SYS_SHM_CREATE`.

### Permission Flow Example

```
Process A (creator):
  SYS_SHM_CREATE(4096) -> handle 3 (RW)
  SYS_SHM_DUP_RO(3)    -> handle 4 (RO)
  send handle 4 to Process B via IPC cap passing

Process B (consumer):
  recv -> handle 2 (RO, installed by kernel)
  SYS_MMAP(handle=2, len=4096) -> maps region read-only (PTE_R|PTE_U)
```

### Enforcement Points

1. **SYS_MMAP**: Checks `rw` flag on the handle. RO handles produce
   read-only PTEs.
2. **SYS_SHM_DUP_RO**: Always produces an RO handle regardless of input.
3. **IPC cap transfer**: The `rw` bit travels with the handle through the
   message queue encoding. The receiver gets exactly the permission the
   sender passed.
4. **Hardware**: The Sv39 page table enforces permissions at the hardware
   level. A store to a page mapped as R-only triggers a store page fault
   (scause = 15).

---

## 8. Region Lifecycle

```
SYS_SHM_CREATE
    |
    v
 ShmRegion { ref_count: 1, active: true }
    |
    |-- SYS_SHM_DUP_RO or IPC cap transfer --> ref_count++
    |
    |-- SYS_MMAP (by any handle holder) --> pages appear in process page table
    |
    |-- SYS_MUNMAP --> pages removed from process page table (frames NOT freed)
    |
    |-- SYS_CHAN_CLOSE on SHM handle --> ref_count--
    |
    v
 ref_count == 0 --> physical frames freed, table slot released
```

### Process Exit Cleanup

When a process exits (`SYS_EXIT`):

1. All SHM-backed mmap regions are unmapped (PTEs cleared, frames NOT freed).
2. All SHM handles in the process's handle table are closed (ref_count
   decremented for each).
3. If any region's ref_count reaches 0, its frames are freed.

This mirrors the existing cleanup for channel handles on process exit.

---

## 9. Usage Examples

### Example 1: Producer-Consumer Shared Buffer

```
Producer (Process A)                     Consumer (Process B)
========================                 ========================
// Create 4 KiB shared region
shm_h = syscall(SHM_CREATE, 4096)
// shm_h is a RW handle

// Map it into our address space
buf = syscall(MMAP, shm_h, 4096)
// buf is a RW mapping

// Create a RO handle for the consumer
ro_h = syscall(SHM_DUP_RO, shm_h)

// Send RO handle to consumer via IPC
msg.cap = ro_h
syscall(CHAN_SEND, consumer_ch, &msg)
                                         // Receive handle from producer
                                         syscall(CHAN_RECV, producer_ch, &msg)
                                         shm_h = msg.cap  // RO handle

                                         // Map the shared region (read-only)
                                         buf = syscall(MMAP, shm_h, 4096)

// Write data to shared buffer
*(buf as *mut u32) = 42
                                         // Read data from shared buffer
                                         let val = *(buf as *u32)  // 42

// Clean up
syscall(MUNMAP, buf, 4096)
syscall(CHAN_CLOSE, shm_h)
                                         syscall(MUNMAP, buf, 4096)
                                         syscall(CHAN_CLOSE, shm_h)
```

### Example 2: Framebuffer Sharing

A framebuffer server could expose its framebuffer via shared memory,
allowing a client to render directly into the buffer without copying:

```
Framebuffer Server                       GUI Client
========================                 ========================
// Allocate framebuffer as SHM
fb_shm = syscall(SHM_CREATE, 800*600*4)
fb_ptr = syscall(MMAP, fb_shm, 800*600*4)

// On client connect, send RW handle
// (client needs to write pixels)
msg.cap = fb_shm
syscall(CHAN_SEND, client_ch, &msg)
                                         // Receive framebuffer handle
                                         syscall(CHAN_RECV, server_ch, &msg)
                                         fb_h = msg.cap  // RW handle

                                         // Map framebuffer
                                         fb = syscall(MMAP, fb_h, 800*600*4)

                                         // Draw directly into framebuffer
                                         fb[0] = 0xFF0000  // red pixel
```

---

## 10. Synchronization

Shared memory provides **no built-in synchronization**. Processes sharing a
region must coordinate access themselves. Recommended patterns:

1. **IPC signaling**: Use a channel alongside the shared region. The producer
   writes data, then sends a "ready" message. The consumer receives the
   message, then reads the data. The channel send/recv provides the necessary
   ordering.

2. **Single-writer / single-reader**: If only one process writes and one
   reads, a simple sequence counter (atomic write by producer, atomic read by
   consumer) suffices. RISC-V's RVWMO memory model requires appropriate fence
   instructions (`fence rw, rw`) between writes and the counter update.

3. **Atomic operations**: RISC-V A-extension atomics (lr/sc, amo*) work on
   shared memory pages and can implement locks or lock-free structures.

---

## 11. Limits Summary (Updated)

| Constant            | Value | Description                              |
|---------------------|-------|------------------------------------------|
| `MAX_HANDLES`       | 32    | Handle table slots per process (channels + SHM) |
| `MAX_PROCS`         | 64    | Maximum number of processes               |
| `MAX_CHANNELS`      | 64    | Maximum simultaneous channels             |
| `MAX_SHM_REGIONS`   | 32    | Maximum simultaneous shared memory regions |
| `MAX_MSG_SIZE`      | 1024  | Maximum message payload (bytes)           |
| `MAX_MMAP_REGIONS`  | 256   | mmap tracking slots per process           |
| `PAGE_SIZE`         | 4096  | Page size (bytes)                         |
| `NO_CAP`            | usize::MAX | Sentinel for "no capability"         |

---

## 12. Syscall Number Summary (Updated)

| Number | Name                   | Description                                           |
|--------|------------------------|-------------------------------------------------------|
| 93     | `SYS_EXIT`             | Terminate process (now also cleans up SHM handles)    |
| 124    | `SYS_YIELD`            | Yield CPU                                             |
| 172    | `SYS_GETPID`           | Get PID                                               |
| 200    | `SYS_CHAN_CREATE`       | Create channel pair                                   |
| 201    | `SYS_CHAN_SEND`         | Send message (cap passing supports SHM handles)       |
| 202    | `SYS_CHAN_RECV`         | Non-blocking receive (cap install supports SHM)       |
| 203    | `SYS_CHAN_CLOSE`        | Close handle (channels or SHM)                        |
| 204    | `SYS_CHAN_RECV_BLOCKING`| Blocking receive (cap install supports SHM)           |
| **205**| **`SYS_SHM_CREATE`**   | **Create shared memory region (returns RW handle)**   |
| **206**| **`SYS_SHM_DUP_RO`**   | **Duplicate SHM handle as read-only**                 |
| 215    | `SYS_MUNMAP`           | Unmap pages (extended for SHM)                        |
| 222    | `SYS_MMAP`             | Map pages (extended: `a0` = SHM handle or 0)          |
