# 0010: Kernel Observability Infrastructure

**Date:** 2026-02-20
**Status:** Complete (2026-02-20)
**Subsystem:** kernel/kstat, kernel/ipc, kernel/task, kernel/services, user/shell

## Motivation

rvOS has crash diagnostics (panic backtraces, `ps`, `mem`) but lacks
performance observability. You can tell *what* crashed but not *why
something is slow* or *what the system is doing right now*. In a
microkernel where every operation is IPC, this is critical — scheduling
latency and IPC delivery time are the system's pulse.

Current gaps:
- No global activity counters (can't answer "is the system busy?")
- `ps` shows Blocked but not *what* a process is blocked on
- No per-channel message/byte stats (can't find the hot service)
- No latency distributions (can't distinguish "always 1ms" from "usually
  10us but sometimes 100ms")
- No documentation of existing tools for future agents/sessions

## Design

### Overview

Four kernel features + documentation, each independently useful:

1. **kstat** — always-on atomic counters for scheduler, IPC, pages, IRQs
2. **Blocked-on introspection** — `BlockReason` enum shown in `ps` output
3. **Per-channel statistics** — message/byte counters per channel
4. **Latency histograms** — log2 bucket histograms for scheduler runqueue
   and IPC delivery latency, with Gregg-style ASCII output

All exposed through the existing sysinfo service protocol (new command
variants) and shell commands.

### Interface Changes

**New sysinfo protocol commands** (lib/rvos-proto/src/sysinfo.rs):

    Kstat(4) {}         — global kernel counters
    Channels(5) {}      — per-channel statistics table
    SchedLatency(6) {}  — scheduler latency histogram
    IpcLatency(7) {}    — IPC delivery latency histogram

All use the existing chunked text response format (no ABI changes).

**New shell commands** (user/shell/src/shell.rs):

    kstat     — display global counters
    chstat    — display per-channel stats
    schedlat  — scheduler latency histogram
    ipclat    — IPC delivery latency histogram

**Modified shell command:**

    ps        — adds BLOCKED ON column for Blocked processes

**No new syscalls.** All data flows through the existing sysinfo service.

### Internal Changes

#### 1. kstat module (NEW: kernel/src/kstat.rs)

Static `AtomicU64` counters with `Relaxed` ordering (compiles to single
`amoadd.d` on RV64 — no fences, no locks). Counters:

| Group | Counters |
|-------|----------|
| Scheduler | SCHED_SWITCHES, SCHED_PREEMPTS, SCHED_YIELDS |
| IPC | IPC_SENDS, IPC_RECVS, IPC_SEND_BLOCKS, IPC_RECV_BLOCKS |
| Channels | CHANNELS_CREATED, CHANNELS_CLOSED |
| Pages | PAGES_ALLOCATED, PAGES_FREED |
| Interrupts | IRQ_TIMER, IRQ_UART, IRQ_VIRTIO_KBD, IRQ_VIRTIO_NET, IRQ_VIRTIO_GPU, IRQ_VIRTIO_BLK, IRQ_PLIC_OTHER |

`Log2Hist` type for latency histograms:
- 32 buckets of `AtomicU64`, bucket[i] = count of values in [2^i, 2^(i+1))
- `record(value)`: `63 - value.leading_zeros()` to find bucket, one atomic add
- `format_histogram()`: ASCII bar chart (Brendan Gregg style)

Global histogram statics: `SCHED_LATENCY`, `IPC_LATENCY`.

Instrumentation points — one `kstat::inc(...)` call at each site:

| Counter | File | Function/site |
|---------|------|---------------|
| SCHED_SWITCHES | task/scheduler.rs | schedule() after picking next_pid |
| SCHED_PREEMPTS | task/scheduler.rs | preempt() after picking next_pid |
| SCHED_YIELDS | arch/syscall/mod.rs | SYS_YIELD handler |
| IPC_SENDS | ipc/mod.rs | channel_send() on success before Ok(...) |
| IPC_RECVS | ipc/mod.rs | channel_recv() when msg.is_some() |
| IPC_SEND_BLOCKS | ipc/mod.rs | channel_set_send_blocked() entry |
| IPC_RECV_BLOCKS | ipc/mod.rs | channel_set_blocked() entry |
| CHANNELS_CREATED | ipc/mod.rs | channel_create_pair() on success |
| CHANNELS_CLOSED | ipc/mod.rs | channel_close() when setting active=false |
| PAGES_ALLOCATED | mm/frame.rs | frame_alloc() on success |
| PAGES_FREED | mm/frame.rs | frame_dealloc() entry |
| IRQ_TIMER | arch/trap.rs | timer_tick() entry |
| IRQ_UART | arch/trap.rs | external_interrupt() UART branch |
| IRQ_VIRTIO_* | arch/trap.rs | external_interrupt() each VirtIO branch |
| IRQ_PLIC_OTHER | arch/trap.rs | external_interrupt() unknown IRQ branch |

#### 2. BlockReason (MODIFY: kernel/src/task/process.rs, scheduler.rs)

New enum on Process:

    pub enum BlockReason {
        None,
        IpcRecv(usize),    // endpoint ID
        IpcSend(usize),    // endpoint ID
        Timer(u64),        // deadline tick
        Poll,              // sys_block (event poll)
        DebugSuspend,
    }

Set at each blocking site (before block_process()):

| Reason | File | Function |
|--------|------|----------|
| IpcRecv(ep) | ipc/mod.rs | channel_recv_blocking() |
| IpcSend(ep) | ipc/mod.rs | channel_send_blocking() |
| IpcRecv(ep) | arch/syscall/chan.rs | sys_chan_recv_blocking() |
| IpcSend(ep) | arch/syscall/chan.rs | sys_chan_send_blocking() |
| Timer(deadline) | task/scheduler.rs | block_with_deadline() |
| Poll | arch/syscall/mod.rs | SYS_BLOCK handler |
| DebugSuspend | arch/trap.rs | debug suspend + breakpoint paths |

Clear in wake_process() and check_deadlines() when transitioning Blocked→Ready.

Update process_list(): add BLOCKED ON column.

#### 3. Per-channel statistics (MODIFY: kernel/src/ipc/mod.rs)

Add to Channel struct:

    msgs_a: u64,   bytes_a: u64,   // delivered to queue_a
    msgs_b: u64,   bytes_b: u64,   // delivered to queue_b

Increment in channel_send() — capture msg.len before push, increment
destination side counters.

New public function: `channel_stats()` returning per-channel snapshot.

#### 4. Latency histograms (MODIFY: ipc/mod.rs, task/scheduler.rs, task/process.rs)

**Scheduler latency:**
- Add `pub enqueue_time: u64` to Process (init 0)
- Set at every ready_queue.push_back() / push_front() site
- Record at pop_front() sites (schedule(), preempt())

**IPC latency:**
- Change queue type: `VecDeque<Message>` → `VecDeque<(Message, u64)>`
- In channel_send(): capture rdtime(), push (msg, send_time)
- In channel_recv(): pop (msg, send_time), record histogram

### Resource Limits

No new fixed-size tables. The Log2Hist uses 32 × AtomicU64 = 256 bytes
(static, not heap). Channel stats Vec is transient (allocated per request,
freed after response). kstat counters are static AtomicU64s (~144 bytes total).

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| New kstat.rs module | main.rs (add mod), kstat.rs (new) | Low (additive) |
| kstat::inc() calls | ipc/mod.rs, task/scheduler.rs, arch/trap.rs, arch/syscall/mod.rs, mm/frame.rs | Low (one-line additions) |
| BlockReason enum + field | task/process.rs, all constructors | Low (additive field) |
| set_block_reason() calls | ipc/mod.rs, arch/syscall/chan.rs, arch/syscall/mod.rs, arch/trap.rs | Low (one-line additions) |
| process_list() format | task/scheduler.rs | Low (output format change) |
| Channel stats fields | ipc/mod.rs Channel struct + Channel::new() | Low (additive fields) |
| Queue type VecDeque<(Message,u64)> | ipc/mod.rs | Medium (several lines, all in one file) |
| enqueue_time field + sets | task/process.rs, task/scheduler.rs | Medium (many sites but mechanical) |
| SysinfoCommand variants | lib/rvos-proto/src/sysinfo.rs | Low (additive enum variants) |
| Sysinfo handler arms | kernel/src/services/sysinfo.rs | Low (new match arms) |
| Shell commands | user/shell/src/shell.rs | Low (new functions + match arms) |

## Acceptance Criteria

- [ ] `make clippy` passes on all crates
- [ ] System boots to shell and existing commands work
- [ ] `kstat` shows nonzero IRQ_TIMER and SCHED_SWITCHES after a few seconds
- [ ] `ps` shows BLOCKED ON column; blocked processes show recv/send/timer/poll
- [ ] `chstat` shows all active channels with message counts > 0
- [ ] `schedlat` shows a histogram with nonzero buckets
- [ ] `ipclat` shows a histogram with nonzero buckets after running a few commands
- [ ] docs/debugging-and-observability.md exists and covers all tools

## Deferred

| Item | Rationale |
|------|-----------|
| Structured trace events | Current string-label ring buffer works; structured events are a larger redesign |
| IPC causality tracing (trace IDs) | Requires protocol changes across all services |
| Per-channel latency histograms | Global histogram sufficient for initial observability |
| Deadlock detection watchdog | Separate feature (0011) |
| kstat reset command | Can add later; current counters are monotonic which is more useful |

## Implementation Notes

(Updated during implementation)

## Verification

(Updated after implementation)
