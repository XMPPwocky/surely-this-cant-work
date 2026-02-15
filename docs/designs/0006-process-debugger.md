# 0006: Process Debugger

**Date:** 2026-02-12
**Status:** Implemented
**Subsystem:** kernel/services, kernel/arch, lib/rvos-proto, user/dbg

## Motivation

rvOS currently has no way to debug user processes interactively. When a
process crashes, the kernel prints a page fault or illegal instruction
message and kills it — there's no way to set breakpoints, inspect
registers, read memory, or step through code. A basic debugger is
essential for developing and debugging user-space applications.

## Design

### Overview

The debugger has two components:

1. **`process-debug` kernel task** — a new kernel service (like sysinfo or
   math) that handles privileged operations: attaching to processes,
   suspending/resuming them, reading/writing registers and memory,
   managing breakpoints, and forwarding debug events (breakpoint hits).

2. **`dbg` user app** — an interactive command-line debugger that connects
   to the process-debug service via IPC and presents a GDB-like interface.

The split keeps the kernel-side minimal (privileged operations only) while
the user app handles all UI, command parsing, and display formatting.

### How It Works

#### Attach / Detach

The debugger attaches to a target process by PID. The kernel service marks
the process as "debugged" by setting fields on its `Process` struct. Only
one debugger can attach to a process at a time. Detaching clears the debug
state and resumes the process if it was suspended.

#### Suspend / Resume

**Forced suspend:** The debugger can suspend a running process. The kernel
sets a `debug_suspend_pending` flag. At the next trap entry (timer
interrupt — at most 100ms — or any syscall/exception), the trap handler
checks the flag, saves the full `TrapFrame` to the `Process` struct,
blocks the process, and notifies the debugger via an event message.

**Resume:** The debugger sends a Resume command. The service copies the
(potentially modified) `TrapFrame` back to the kernel-stack location,
wakes the process, and the trap handler's normal return path restores
registers and `sret`s back to user mode.

**Breakpoint suspend:** When a debugged process executes an `ebreak`
instruction (software breakpoint), the trap handler (scause=3) saves the
TrapFrame, blocks the process, and notifies the debugger. The process
stays suspended until the debugger sends Resume.

#### Registers

When a process is suspended (at a breakpoint or forced-suspend), its full
register file is available in the saved `TrapFrame`: all 32 general-
purpose registers (x0–x31), `sstatus`, and `sepc` (program counter).

The debugger can read all registers or write individual registers. Writes
modify the saved TrapFrame; the changes take effect when the process
resumes.

#### Memory

Since rvOS uses identity mapping (VA == PA), the kernel task can directly
read/write any mapped user memory. The service validates addresses by
walking the target process's page table (`user_satp`) to confirm the page
is mapped with the U (user) bit. This prevents reading kernel memory or
unmapped regions through the debugger.

Memory reads return up to 512 bytes per request (fitting in a single
1024-byte message with overhead). Larger reads require multiple requests.

#### Breakpoints

RISC-V software breakpoints use the `c.ebreak` instruction (0x9002, 2
bytes, compressed). The breakpoint mechanism:

1. **Set:** Save the original 2 bytes at the target address. Write
   `0x9002` (`c.ebreak`). Execute `fence.i` to flush the I-cache.
2. **Hit:** The process traps with scause=3. The trap handler checks if the
   process is debugged; if so, it saves state and notifies the debugger.
   `sepc` points to the `c.ebreak` instruction.
3. **Resume past breakpoint:** Before resuming, the service restores the
   original 2 bytes, sets `sepc` to the breakpoint address (so it
   re-executes the original instruction), and resumes. If the breakpoint
   should persist, the service re-installs it after the process executes
   one instruction (using a single-step-like mechanism with a temporary
   breakpoint at the next instruction — deferred to future work; for now,
   resuming from a breakpoint clears it).
4. **Clear:** Restore the original 2 bytes, execute `fence.i`.

Maximum 8 breakpoints per attached process (basic version).

#### Backtrace

The service walks the frame pointer chain starting from the saved `s0`
(fp) register. At each frame:

- `[fp - 8]` = saved `ra` (return address)
- `[fp - 16]` = saved previous `fp`

Each address is validated against the target's page table. The walk stops
when `fp` is zero, not page-aligned, or outside user memory. Returns up to
32 frames.

This requires user code to be compiled with `-C force-frame-pointers=yes`.
The rvOS user toolchain already sets this for kernel code; the user target
spec should also enable it (check and document).

### Interface Changes

#### New IPC Protocol: `process-debug`

Service name: `"process-debug"` (registered in init's named services).

The protocol follows the filesystem pattern with two levels of channels:

1. **Control channel** — obtained via `connect_to_service("process-debug")`.
   Used only for `Attach`. Returns a per-process **session channel**
   capability (plus an **event channel** for async notifications).

2. **Session channel** — one per attached process. All debug commands
   (suspend, resume, read registers, breakpoints, etc.) go here. PID is
   implicit — it was established during attach. Closing this channel
   detaches from the process. Uses `define_protocol!` for typed RPC.

3. **Event channel** — push-only, server → debugger. Receives async
   notifications (breakpoint hit, process exited, forced suspend
   completed). The debugger polls this alongside stdin for interactivity.

Protocol defined in `lib/rvos-proto/src/debug.rs`:

```rust
// ── Control channel (attach handshake) ──────────────────────────

define_message! {
    /// Attach request on the control channel.
    pub struct DebugAttachRequest { pid: u32 }
}

define_message! {
    /// Attach response on the control channel.
    /// On success, embeds a session channel and an event channel.
    pub owned enum DebugAttachResponse {
        /// Attach succeeded. Use session_channel for commands,
        /// event_channel for async notifications.
        Ok(0)    { session: RawChannelCap, events: RawChannelCap },
        /// Attach failed (process not found, already attached, etc.)
        Error(1) { code: DebugError },
    }
}

define_message! {
    pub enum DebugError {
        NotFound(0)        {},
        AlreadyAttached(1) {},
        NotAUserProcess(2) {},
        NoResources(3)     {},
    }
}

// ── Session channel (per-process debug commands) ────────────────

define_message! {
    /// Requests on the per-process session channel.
    pub enum SessionRequest<'a> => SessionRequestMsg {
        Suspend(0)         {},
        Resume(1)          {},
        ReadRegisters(2)   {},
        WriteRegister(3)   { reg: u8, value: u64 },
        ReadMemory(4)      { addr: u64, len: u32 },
        WriteMemory(5)     { addr: u64, data: &'a [u8] },
        SetBreakpoint(6)   { addr: u64 },
        ClearBreakpoint(7) { addr: u64 },
        Backtrace(8)       {},
    }
}

define_message! {
    /// Responses on the per-process session channel.
    pub enum SessionResponse<'a> => SessionResponseMsg {
        Ok(0)         {},
        Error(1)      { message: &'a str },
        Registers(2)  { pc: u64, regs: [u64; 32] },
        Memory(3)     { data: &'a [u8] },
        Backtrace(4)  { frames: &'a [u8] },  // packed [(ra: u64, fp: u64); N]
    }
}

define_protocol! {
    /// Per-process debug session protocol.
    pub protocol DebugSession => DebugSessionClient, DebugSessionHandler,
                                 debug_session_dispatch, debug_session_handle {
        type Request<'a> = SessionRequest;
        type Response<'a> = SessionResponse;

        rpc suspend as Suspend() -> SessionResponse<'_>;
        rpc resume as Resume() -> SessionResponse<'_>;
        rpc read_registers as ReadRegisters() -> SessionResponse<'_>;
        rpc write_register as WriteRegister(reg: u8, value: u64) -> SessionResponse<'_>;
        rpc read_memory as ReadMemory(addr: u64, len: u32) -> SessionResponse<'_>;
        rpc write_memory as WriteMemory(addr: u64, data: &[u8]) -> SessionResponse<'_>;
        rpc set_breakpoint as SetBreakpoint(addr: u64) -> SessionResponse<'_>;
        rpc clear_breakpoint as ClearBreakpoint(addr: u64) -> SessionResponse<'_>;
        rpc backtrace as Backtrace() -> SessionResponse<'_>;
    }
}

// ── Event channel (async push from service to debugger) ─────────

define_message! {
    /// Async events pushed on the event channel.
    pub enum DebugEvent {
        /// Target hit a breakpoint at `addr`.
        BreakpointHit(0)  { addr: u64 },
        /// Target was force-suspended (in response to Suspend command).
        Suspended(1)      {},
        /// Target process exited.
        ProcessExited(2)  { exit_code: i32 },
    }
}
```

**Usage flow:**

```
Debugger              control channel          process-debug service
    |                       |                          |
    |-- AttachRequest{5} -->|------------------------->|  (mark PID 5 as debugged,
    |                       |                          |   create session + event channels)
    |<-- AttachResponse ----|<-------------------------|
    |    Ok { session, events }                        |
    |                       |                          |
    |   (close control channel — done with it)         |
    |                                                  |
    |                session channel                   |
    |                       |                          |
    |-- SetBreakpoint ----->|------------------------->|  (save insn, write c.ebreak)
    |<-- Ok {} -------------|<-------------------------|
    |                       |                          |
    |-- Resume ------------>|------------------------->|  (wake process)
    |<-- Ok {} -------------|<-------------------------|
    |                       |                          |
    |                event channel                     |
    |                       |                          |
    |   ... process runs, hits breakpoint ...          |
    |                       |                          |
    |<-- BreakpointHit -----|<-------------------------|  (async push)
    |                       |                          |
    |                session channel                   |
    |                       |                          |
    |-- ReadRegisters ----->|------------------------->|
    |<-- Registers {} ------|<-------------------------|
    |                       |                          |
    |-- ReadMemory -------->|------------------------->|
    |<-- Memory {} ---------|<-------------------------|
    |                       |                          |
    |   (close session channel → auto-detaches)        |
```

#### No New Syscalls

All debugger functionality uses existing IPC syscalls. The kernel service
has direct access to kernel data structures (scheduler, process table,
page tables) — no new syscalls are needed.

#### Trap Handler Changes

The trap handler (`kernel/src/arch/trap.rs`) gains two new code paths:

1. **Breakpoint exception (scause=3, U-mode):** If the process has
   `debug_attached == true`, save TrapFrame to `Process.debug_trap_frame`,
   block the process, notify the debugger, and schedule away. If not
   attached, existing behavior (kill process).

2. **Debug suspend check (all U-mode traps):** At the end of
   `trap_handler`, before returning to user mode, check
   `debug_suspend_pending`. If set, save TrapFrame, block, notify, schedule.

### Internal Changes

#### Process struct additions (`kernel/src/task/process.rs`)

```rust
pub const MAX_BREAKPOINTS: usize = 8;

pub struct Process {
    // ... existing fields ...

    // Debug state
    pub debug_attached: bool,
    pub debug_event_ep: usize,       // event channel endpoint (service → debugger)
    pub debug_suspend_pending: bool,  // set by Suspend command, checked by trap handler
    pub debug_suspended: bool,        // currently suspended for debugging
    pub debug_trap_frame: Option<[usize; 34]>,  // saved TrapFrame (32 regs + sstatus + sepc)
    pub debug_breakpoints: [(usize, u16); MAX_BREAKPOINTS],  // (addr, original_2_bytes)
    pub debug_breakpoint_count: usize,
}
```

All debug fields are initialized to defaults (false, 0, None, empty) in
`Process::new_kernel()`, `new_user()`, and `new_user_elf()`.

#### New scheduler functions (`kernel/src/task/scheduler.rs`)

```rust
/// Get debug state for a process by PID.
pub fn process_debug_attached(pid: usize) -> bool;

/// Set debug state for a process (attach/detach).
/// event_ep is the service-side endpoint of the event channel for this session.
pub fn set_process_debug_state(pid: usize, attached: bool, event_ep: usize);

/// Set debug_suspend_pending for a process.
pub fn set_debug_suspend_pending(pid: usize, pending: bool);

/// Check and clear debug_suspend_pending (called from trap handler).
/// Returns the event endpoint to notify, if pending was set.
pub fn check_debug_suspend_pending() -> Option<usize>;

/// Save TrapFrame to process debug state.
pub fn save_debug_trap_frame(pid: usize, tf: &TrapFrame);

/// Read saved TrapFrame from process debug state.
pub fn read_debug_trap_frame(pid: usize) -> Option<[usize; 34]>;

/// Write a single register in saved TrapFrame.
pub fn write_debug_register(pid: usize, reg: u8, value: usize) -> bool;

/// Get user_satp for a specific process (not just current).
pub fn process_user_satp(pid: usize) -> usize;

/// Get the event endpoint for a debugged process (for trap handler use).
pub fn process_debug_event_ep(pid: usize) -> Option<usize>;

/// Read/write breakpoint table for a process.
pub fn process_debug_breakpoints(pid: usize) -> [(usize, u16); MAX_BREAKPOINTS];
pub fn set_process_debug_breakpoints(pid: usize, bp: [(usize, u16); MAX_BREAKPOINTS], count: usize);
```

#### New kernel service (`kernel/src/services/proc_debug.rs`)

Follows the two-level channel pattern (like the filesystem service):

```rust
static PROC_DEBUG_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) { ... }

pub fn proc_debug_service() {
    let control_ep = PROC_DEBUG_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    loop {
        // Accept a client on the control channel
        let accepted = ipc::accept_client(control_ep, my_pid);
        let client_ep = OwnedEndpoint::new(accepted.endpoint);

        // Receive DebugAttachRequest
        let msg = ipc::channel_recv_blocking(client_ep.raw(), my_pid);
        let req: DebugAttachRequest = deserialize(&msg);

        // Validate: process exists, is a user process, not already attached
        if !valid_target(req.pid) {
            send_error(client_ep.raw(), ...);
            continue;  // drop client_ep, go back to accept
        }

        // Create session channel pair + event channel pair
        let (session_a, session_b) = ipc::channel_create();
        let (event_a, event_b) = ipc::channel_create();

        // Mark target as debugged, store event_a for trap handler to push events
        set_process_debug_state(req.pid, true, event_a);

        // Send DebugAttachResponse::Ok with session_b + event_b caps to client
        // (session_b = client's session endpoint, event_b = client's event endpoint)
        send_attach_ok(client_ep.raw(), session_b, event_b);

        // Enter session loop — process commands on session_a until disconnect
        let session_ep = OwnedEndpoint::new(session_a);
        handle_debug_session(session_ep.raw(), req.pid, event_a, my_pid);

        // Session ended (client closed channel or explicit cleanup)
        // Detach: clear debug state, resume if suspended, close event channel
        detach_process(req.pid, event_a);
    }
}
```

`handle_debug_session` loops receiving `SessionRequest` messages on the
session endpoint and dispatching them (suspend, resume, read registers,
breakpoints, etc.). When the client closes the session channel, the recv
fails and the loop exits, triggering auto-detach.

The event channel (`event_a`, held by the service) is also used by the
trap handler: when a breakpoint is hit or a forced suspend completes, the
trap handler sends a `DebugEvent` message on the event endpoint stored in
`Process.debug_event_ep`. The debugger reads events from `event_b`.

#### New heap allocator tag

`DBUG` tag for debug service allocations (in `kernel/src/mm/heap.rs`).

#### New user app (`user/dbg/`)

Interactive debugger with commands:

| Command | Description |
|---------|-------------|
| `attach <pid>` | Attach to a process (opens session + event channels) |
| `detach` | Detach from current process (closes session channel) |
| `break <addr>` | Set breakpoint at hex address |
| `clear <addr>` | Clear breakpoint |
| `continue` / `c` | Resume execution |
| `suspend` / `s` | Force-suspend the process |
| `regs` | Display all registers |
| `setreg <name> <val>` | Set a register (e.g., `setreg a0 0x42`) |
| `mem <addr> [len]` | Display memory (hex dump), default 64 bytes |
| `write <addr> <hex>` | Write hex bytes to memory |
| `bt` | Show backtrace |
| `help` | Show available commands |

### Resource Limits

| Limit | Value | Exhaustion Behavior |
|-------|-------|-------------------|
| MAX_BREAKPOINTS | 8 per process | SetBreakpoint returns Error("too many breakpoints") |
| Max memory read | 512 bytes/request | Client issues multiple requests for larger reads |
| Max backtrace depth | 32 frames | Walk stops, returns partial backtrace |
| Concurrent debug sessions | 1 (single client at a time) | Second client blocks on accept_client until first session ends |
| Channels per session | 2 (session + event) | Created on attach, closed on detach |

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| Add debug fields to Process struct | `kernel/src/task/process.rs` (1 file) | Low — additive fields, initialized to defaults |
| New scheduler accessor functions | `kernel/src/task/scheduler.rs`, `kernel/src/task/mod.rs` | Low — new public fns, no changes to existing |
| Trap handler: breakpoint + suspend check | `kernel/src/arch/trap.rs` | **Medium** — modifies hot path; must not slow normal traps |
| New kernel service (two-channel pattern) | `kernel/src/services/proc_debug.rs`, `mod.rs`, `main.rs` | Low — additive |
| New protocol | `lib/rvos-proto/src/debug.rs`, `lib.rs` | Low — new file |
| New user app | `user/dbg/`, `user/Cargo.toml` | Low — additive |
| Embed dbg in fs | `user/fs/src/main.rs` | Low — one `include_bytes!` line |
| New heap tag | `kernel/src/mm/heap.rs` | Low — additive |
| Init service registration | `kernel/src/main.rs` | Low — 4 lines following existing pattern |

**Performance concern:** The debug suspend check in the trap handler runs
on every U-mode trap. It must be a single branch on a bool field — no lock
acquisition in the fast path. The flag is checked via a new function that
uses `try_lock` or an atomic field.

**Implementation note:** `debug_suspend_pending` should be an
`AtomicBool` on the `Process` struct (or a separate static indexed by PID)
so the trap handler can check it without acquiring the scheduler lock.
However, since rvOS is single-core and interrupts are disabled during
trap handling, a plain `bool` checked under `SCHEDULER.lock()` is
acceptable — the lock is already acquired in nearby syscall paths. If
profiling shows this is too slow, it can be upgraded to an atomic.

## Acceptance Criteria

- [ ] `make build` succeeds with all new code
- [ ] `make clippy` passes with no new warnings
- [ ] System boots and reaches shell normally (no regression)
- [ ] `dbg` binary is available as `/bin/dbg` in the filesystem
- [ ] Shell can run `dbg` and the debugger displays a prompt
- [ ] `attach <pid>` successfully attaches to a running user process
- [ ] `suspend` stops the target process (verified: process stops appearing
      in `ps` as Running, debugger receives Suspended event)
- [ ] `regs` shows all 32 registers + PC for a suspended process
- [ ] `setreg` modifies a register and the change is visible in `regs`
- [ ] `mem <addr>` reads and displays target process memory
- [ ] `write <addr> <hex>` writes to target process memory and is verified
      by a subsequent `mem` read
- [ ] `break <addr>` sets a breakpoint; `continue` runs until hit; debugger
      receives BreakpointHit event
- [ ] `bt` shows a valid backtrace with return addresses
- [ ] `detach` closes the session channel, auto-resumes the process, and
      the debugger returns to the unattached prompt
- [ ] Debugging does not crash the kernel or the target process (other than
      intentional breakpoints)
- [ ] A non-debugged process hitting `ebreak` is still killed (existing
      behavior preserved)
- [ ] `make bench` shows no significant regression (> 20%)
- [ ] Process exit while debugged: debugger receives ProcessExited event,
      debug state is cleaned up

## Deferred

| Item | Rationale |
|------|-----------|
| Single-stepping | Requires instruction decoding to find next PC (branches, jumps); complex for basic version |
| Watchpoints (data breakpoints) | RISC-V Sdtrig extension not available on QEMU virt |
| Symbol lookup (function names in backtrace) | Requires loading ELF symbol tables; significant complexity |
| Conditional breakpoints | Requires expression evaluation; can be added later |
| Multi-process debugging | One attach at a time is sufficient for basic version |
| Remote debugging (GDB RSP) | Would require serial protocol support; too complex for first version |
| Breakpoint persistence across resume | Requires single-step-one-instruction mechanism; deferred with single-stepping |

## Implementation Notes

- **No `debug_trap_frame` field:** The design proposed an `Option<[usize; 34]>`
  field to save the TrapFrame. In practice this is unnecessary — when a
  process is blocked (suspended), its registers are already saved in the
  `TrapContext.frame` by the trap handler. The service reads/writes them
  directly via scheduler accessors (`read_debug_trap_frame`,
  `write_debug_register`, `write_debug_sepc`).

- **Register serialization:** The `SessionResponse::Registers` variant
  carries `data: &[u8]` (264 bytes = 1 u64 PC + 32 u64 GPRs, little-endian
  packed) rather than `[u64; 32]`, because `rvos-wire` doesn't have
  `Serialize`/`Deserialize` impls for fixed-size arrays larger than basic
  types.

- **Capability transfer in attach response:** The kernel service manually
  builds the response message with `rvos_wire::to_bytes` (using placeholder
  cap values), then overwrites `msg.caps[]` with
  `ipc::encode_cap_channel()` and calls `ipc::channel_inc_ref()` for each
  cap before sending. This follows the kernel-internal cap transfer pattern
  documented in CLAUDE.md.

- **Shell raw mode fix:** The shell runs in raw mode for line editing. When
  spawning a child process via `run`, it must switch to cooked mode first
  so the child's `read_line()` receives `\n`-terminated lines. The shell
  restores raw mode after the child exits.

- **Event delivery from trap handler:** Uses non-blocking `channel_send`
  (best-effort). If the event channel is full, the event is silently
  dropped. The debugger can always query state explicitly.

- **`debug_suspend_pending` is a plain `bool`:** Checked under the scheduler
  lock in the trap handler. Since rvOS is single-core and the trap handler
  runs with interrupts disabled, no atomics are needed.

## Verification

- `make build` succeeds with no errors
- `make clippy` passes with no warnings
- System boots to shell normally (no regression)
- `run /bin/dbg` launches the debugger, displays prompt (`dbg)`)
- `help` command shows all available commands
- `quit` exits the debugger and returns to shell
- Service registered as PID 5 ("proc-debug") visible in boot log
