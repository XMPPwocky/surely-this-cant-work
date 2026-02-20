# Debugging and Observability

This document covers all debugging and observability tools available in rvOS,
both at the shell and in kernel internals.

---

## Shell Commands

### ps — Process List

Shows all processes with PID, state, CPU usage (EWMA), memory, blocked-on
reason, and name.

```
> ps
  PID  STATE     CPU1s  CPU1m  MEM     BLOCKED ON     NAME
  ---  --------  -----  -----  ------  -------------  ----------------
    0  Ready      0.0%   0.0%     0K                  idle
    1  Running    5.2%   3.1%   144K                  init
    2  Blocked    0.0%   0.1%    16K  recv(ep 4)      serial-con
    3  Blocked    0.0%   0.0%    48K  recv(ep 12)     fs
    4  Ready      0.5%   0.3%    32K                  shell
```

**BLOCKED ON column** shows what blocked processes are waiting for:
- `recv(ep N)` — waiting to receive on channel endpoint N
- `send(ep N)` — waiting to send (queue full) on endpoint N
- `timer(+Nms)` — sleeping for N milliseconds
- `poll` — blocked in `sys_block` (event poll loop)
- `debug` — suspended by debugger

### mem — Memory Statistics

Shows kernel heap statistics (per-tag breakdown) and per-process memory.

```
> mem
Kernel heap: 1024K total, 312K used (30%), 712K free
  Tag     Current    Peak  Allocs
  ----  ---------  ------  ------
  IPC_      128K   256K      23
  SCHD       32K    32K       2
  PGTB       48K    48K      12
```

### kstat — Kernel Counters

Shows global atomic counters for scheduler, IPC, channels, pages, and IRQs.
Counters are monotonic (never reset) and lock-free (`amoadd.d` on RV64).

```
> kstat
=== Kernel Statistics ===
SCHED_SWITCHES       1234
SCHED_PREEMPTS        567
SCHED_YIELDS           89
IPC_SENDS            4521
IPC_RECVS            4520
IPC_SEND_BLOCKS         3
IPC_RECV_BLOCKS      1205
CHANNELS_CREATED       28
CHANNELS_CLOSED        12
PAGES_ALLOCATED       892
PAGES_FREED           340
IRQ_TIMER           15234
IRQ_UART              127
IRQ_VIRTIO_KBD         45
IRQ_VIRTIO_NET          0
IRQ_VIRTIO_GPU        312
IRQ_VIRTIO_BLK          0
IRQ_PLIC_OTHER          0
```

### chstat — Channel Statistics

Shows all active (and recently closed) channels with queue depths, ref counts,
and cumulative message/byte counters per side.

```
> chstat
    CH   EP_A   EP_B    QA    QB  RC_A  RC_B   MSGS_A  BYTES_A   MSGS_B  BYTES_B
  ----  -----  -----  ----  ----  ----  ----  -------  -------  -------  -------
     0      0      1     0     0     3     1      452    28416      123     7812
     1      2      3     0     1     1     1       89     5340       90     5400
```

- **CH**: Channel index
- **EP_A/EP_B**: Global endpoint IDs (EP = CH*2 and CH*2+1)
- **QA/QB**: Current queue depths (messages pending recv)
- **RC_A/RC_B**: Reference counts per endpoint
- **MSGS_A/BYTES_A**: Cumulative messages/bytes delivered to queue_a (from B→A sends)
- **MSGS_B/BYTES_B**: Cumulative messages/bytes delivered to queue_b (from A→B sends)

### schedlat — Scheduler Latency Histogram

Shows a log2 histogram of scheduler runqueue latency (time from
`push_back`/`push_front` to `pop_front` in scheduler). Measured in
microseconds (10 MHz clock / 10 ticks per us).

```
> schedlat
=== Scheduler Runqueue Latency (us) distribution ===
         us           : count    distribution
         0 -> 1       : 234    |****                            |
         1 -> 2       : 1823   |*****************************   |
         2 -> 4       : 2105   |********************************|
         4 -> 8       : 856    |*************                   |
         8 -> 16      : 123    |**                              |
        16 -> 32      : 45     |*                               |
        32 -> 64      : 12     |                                |
        64 -> 128     : 3      |                                |
```

### ipclat — IPC Delivery Latency Histogram

Shows a log2 histogram of IPC message delivery latency (time from
`channel_send` to `channel_recv`). Measured in microseconds.

```
> ipclat
=== IPC Delivery Latency (us) distribution ===
         us           : count    distribution
         0 -> 1       : 89     |***                             |
         1 -> 2       : 1456   |*****************************   |
         2 -> 4       : 1678   |********************************|
         4 -> 8       : 423    |********                        |
         8 -> 16      : 67     |*                               |
        16 -> 32      : 12     |                                |
```

### trace — Trace Buffer

Shows the kernel's trace ring buffer entries (timestamp, PID, label).
Used for debugging kernel internals.

```
> trace
  TICK       PID  LABEL
  --------  ----  ----------------
  12345678     1  sched-switch
  12345690     3  ipc-send
  12345712     3  ipc-recv
```

### trace-clear — Clear Trace Buffer

Clears the kernel trace ring buffer.

---

## Interactive Debugger (dbg)

The `dbg` shell command attaches to a running user process for interactive
debugging. See `docs/protocols/debug.md` for the protocol specification.

```
> dbg <pid>
```

Debugger commands:
- `regs` — show all registers
- `step` — single-step one instruction
- `cont` / `c` — continue execution
- `break <addr>` — set breakpoint
- `del <n>` — delete breakpoint
- `read <addr> [len]` — read memory
- `write <addr> <bytes>` — write memory
- `bt` — backtrace (frame pointer chain)
- `detach` / `quit` — detach and exit

---

## Benchmarking

### bench — Run Benchmarks

The `bench` command runs the built-in benchmark suite measuring IPC
round-trip latency, channel throughput, spawn latency, and memory
allocation speed.

```
> bench
```

Also available via `make bench` which boots QEMU, runs `/bin/bench`,
and shuts down automatically.

### Regression Testing

After code changes, run `make bench` and compare results against previous
runs. A regression > 20% on any benchmark warrants investigation.

---

## Crash Diagnostics

### Panic Handler

Kernel panics print the panic message, file/line, and trigger a backtrace
from the frame pointer chain. The backtrace shows return addresses (`ra`)
and frame pointers (`fp`) for each stack frame.

### Stack Overflow Detection

When a store page fault occurs at an address near the current `sp`, the
trap handler identifies it as a likely stack overflow and prints
`>>> KERNEL STACK OVERFLOW <<<` before the backtrace. Each kernel task
has a guard page at the bottom of its stack that triggers a fault on
overflow.

---

## Kernel Internals Quick Reference

### kstat Counters

Defined in `kernel/src/kstat.rs`. All are `AtomicU64` with `Relaxed`
ordering (single `amoadd.d` instruction on RV64). Never reset.

| Counter | Incremented In | Meaning |
|---------|---------------|---------|
| SCHED_SWITCHES | scheduler.rs `schedule()` | Context switches (excludes same-task) |
| SCHED_PREEMPTS | scheduler.rs `preempt()` | Timer preemption switches |
| SCHED_YIELDS | syscall/mod.rs `SYS_YIELD` | Voluntary yields |
| IPC_SENDS | ipc/mod.rs `channel_send()` | Successful message sends |
| IPC_RECVS | ipc/mod.rs `channel_recv()` | Successful message receives |
| IPC_SEND_BLOCKS | ipc/mod.rs `channel_set_send_blocked()` | Processes blocked on full queue |
| IPC_RECV_BLOCKS | ipc/mod.rs `channel_set_blocked()` | Processes blocked waiting for message |
| CHANNELS_CREATED | ipc/mod.rs `channel_create_pair()` | Channel pairs created |
| CHANNELS_CLOSED | ipc/mod.rs `channel_close()` | Channels deactivated (last ref closed) |
| PAGES_ALLOCATED | mm/frame.rs `frame_alloc()` | Physical pages allocated |
| PAGES_FREED | mm/frame.rs `frame_dealloc()` | Physical pages freed |
| IRQ_TIMER | trap.rs `timer_tick()` | Timer interrupts |
| IRQ_UART | trap.rs `external_interrupt()` | UART interrupts |
| IRQ_VIRTIO_KBD | trap.rs `external_interrupt()` | VirtIO keyboard interrupts |
| IRQ_VIRTIO_NET | trap.rs `external_interrupt()` | VirtIO network interrupts |
| IRQ_VIRTIO_GPU | trap.rs `external_interrupt()` | VirtIO GPU interrupts |
| IRQ_VIRTIO_BLK | trap.rs `external_interrupt()` | VirtIO block device interrupts |
| IRQ_PLIC_OTHER | trap.rs `external_interrupt()` | Unrecognized PLIC interrupts |

### Latency Histograms

`Log2Hist` in `kernel/src/kstat.rs`: 32 buckets of `AtomicU64`.
Bucket `i` counts values in `[2^i, 2^(i+1))`. Bucket 0 counts values
of 0 or 1.

Two global histograms:
- `SCHED_LATENCY`: time in ready queue (rdtime ticks)
- `IPC_LATENCY`: time from send to recv (rdtime ticks)

Displayed as Brendan Gregg-style ASCII bar charts via the `schedlat`
and `ipclat` shell commands.

### Per-Channel Statistics

Each `Channel` struct tracks `msgs_a`/`bytes_a`/`msgs_b`/`bytes_b`
(cumulative, non-atomic u64 — protected by the CHANNELS SpinLock).
Incremented in `channel_send()`, displayed via `chstat`.

### BlockReason Enum

```rust
pub enum BlockReason {
    None,
    IpcRecv(usize),    // endpoint ID
    IpcSend(usize),    // endpoint ID
    Timer(u64),        // deadline tick
    Poll,              // sys_block (event poll)
    DebugSuspend,
}
```

Set before `block_process()` at all blocking sites, cleared in
`wake_process()` and `check_deadlines()`. Displayed in `ps` output.

### Sysinfo Service Protocol

All observability data flows through the sysinfo service (no new syscalls).
See `docs/protocols/sysinfo.md` for the full protocol specification.
