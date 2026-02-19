# Timer Protocol

The **timer** service is a kernel task that provides timed wakeups via IPC.
Clients request a delay and receive a notification when the duration has
elapsed.

Service name: `"timer"`

Protocol definition: `lib/rvos-proto/src/timer.rs`

## Connection

1. Connect to the `"timer"` named service via the boot channel.
2. The service creates a per-client channel pair and accepts the connection.
3. Send `TimerRequest` messages on the per-client channel.

The service supports up to **32 concurrent clients** (`MAX_TIMER_CLIENTS`).

## Messages

**TimerRequest** (client → timer):

| Tag | Name  | Fields              | Description                      |
|-----|-------|---------------------|----------------------------------|
| 0   | After | `duration_us: u64`  | Request wakeup after N microseconds |

**TimerResponse** (timer → client):

| Tag | Name    | Fields | Description               |
|-----|---------|--------|---------------------------|
| 0   | Expired |        | The requested time elapsed |

## Usage Pattern

```
// One-shot timer
Send: After { duration_us: 50_000 }   // 50ms
Recv: Expired {}                        // woken after ~50ms

// Repeated timers on the same channel
Send: After { duration_us: 100_000 }
Recv: Expired {}
Send: After { duration_us: 200_000 }
Recv: Expired {}
```

Each channel supports one pending timer at a time. Sending a new `After`
request while one is pending replaces the previous deadline.

## Implementation Notes

- The service uses `block_with_deadline` for efficient sleeping — the
  scheduler re-arms the SBI timer for precise wakeup when the deadline
  is sooner than the next regular 100ms tick.
- Timer resolution depends on rdtime tick frequency (10 MHz on QEMU
  virt, so 1 tick = 0.1 us).
- Deadline arithmetic uses `saturating_add`/`saturating_mul` to prevent
  overflow on large `duration_us` values.
- Timer channels can be multiplexed with other channels using
  `sys_chan_poll_add` + `sys_block` for reactor-style event loops.

## Constants

Defined in `kernel/src/services/timer.rs`:

```
MAX_TIMER_CLIENTS = 32
TICKS_PER_US      = 10     (QEMU virt aclint-mtimer @ 10 MHz)
```
