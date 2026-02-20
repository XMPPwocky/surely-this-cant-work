# Sysinfo Protocol

This document specifies the IPC protocol between user-mode clients and the
sysinfo kernel service. The sysinfo service provides system introspection
(process listing, trace buffer access).

---

## Overview

The sysinfo service is a kernel task that accepts one request per connection
and responds with a chunked text response. After the response is complete,
the client closes the channel.

```
  Client                      Sysinfo Service
    |                               |
    |--- "PS" -------------------->|
    |<-- chunk 1 (text) -----------|
    |<-- chunk 2 (text) -----------|
    |<-- sentinel (len=0) ---------|
    |                               |
    |--- sys_chan_close(handle) --->|
```

---

## Service Discovery

Clients request the sysinfo service from the init server on handle 0:

```
send(handle_0, Message { data: "sysinfo", len: 7 })
recv(handle_0) → Message { cap: sysinfo_handle }
```

All subsequent operations use `sysinfo_handle`.

---

## Commands

Commands use the `SysinfoCommand` enum from `rvos-proto::sysinfo`, serialized
with `rvos-wire`:

```rust
define_message! {
    pub enum SysinfoCommand {
        Ps(0) {},
        Memstat(1) {},
        Trace(2) {},
        TraceClear(3) {},
        Kstat(4) {},
        Channels(5) {},
        SchedLatency(6) {},
        IpcLatency(7) {},
    }
}
```

### Ps — Process List

Returns a formatted text table of all processes with their PID, state,
CPU usage (1-second and 1-minute EWMA), memory usage, blocked-on reason,
and name.

**Request:** `SysinfoCommand::Ps {}`

**Response:** Chunked text (see [Response Format](#response-format)).

Example output:

```
  PID  STATE     CPU1s  CPU1m  MEM     BLOCKED ON     NAME
  ---  --------  -----  -----  ------  -------------  ----------------
    0  Ready      0.0%   0.0%     0K                  idle
    1  Running   12.3%   8.5%   144K                  init
    2  Blocked    0.0%   0.1%    16K  recv(ep 4)      serial-con
    3  Ready      0.5%   0.3%    48K                  fs
```

**Columns:**

| Column | Description |
|--------|-------------|
| PID    | Process ID (0 = idle task) |
| STATE  | Ready, Running, Blocked, or Dead |
| CPU1s  | CPU usage over a 1-second EWMA window (0.0%–100.0%) |
| CPU1m  | CPU usage over a 1-minute EWMA window (0.0%–100.0%) |
| MEM    | Total physical pages owned, in KiB (pages × 4K) |
| BLOCKED ON | What a Blocked process is waiting for (empty if not blocked) |
| NAME   | Process name (max 16 chars) |

### Memstat — Kernel Memory Statistics

Returns kernel heap statistics (per-tag breakdown) and per-process
physical memory usage.

**Request:** `SysinfoCommand::Memstat {}`

**Response:** Chunked text (see [Response Format](#response-format)).

Example output:

```
Kernel heap: 1024K total, 312K used (30%), 712K free
  Tag     Current    Peak  Allocs
  ----  ---------  ------  ------
  ????       96K   128K      38
  IPC_      128K   256K      23
  SCHD       32K    32K       2
  PGTB       48K    48K      12

Process memory:
  PID  NAME              MEM
  ---  ----------------  ------
    0  idle                 0K
    1  init               144K
    5  fs                 476K
    6  shell-serial       140K
```

### Trace — Read Trace Buffer

Returns the contents of the kernel's trace ring buffer as formatted text.
Each line contains a timestamp, PID, and trace label.

**Request:** `SysinfoCommand::Trace {}`

**Response:** Chunked text (see [Response Format](#response-format)).

### TraceClear — Clear Trace Buffer

Clears the kernel trace ring buffer and responds with `"ok\n"`.

**Request:** `SysinfoCommand::TraceClear {}`

**Response:** Chunked text containing `"ok\n"`.

### Kstat — Kernel Counters

Returns global atomic counters for scheduler, IPC, channels, memory pages,
and interrupts. All counters are monotonic (never reset).

**Request:** `SysinfoCommand::Kstat {}`

**Response:** Chunked text (see [Response Format](#response-format)).

Counters include: SCHED_SWITCHES, SCHED_PREEMPTS, SCHED_YIELDS, IPC_SENDS,
IPC_RECVS, IPC_SEND_BLOCKS, IPC_RECV_BLOCKS, CHANNELS_CREATED,
CHANNELS_CLOSED, PAGES_ALLOCATED, PAGES_FREED, IRQ_TIMER, IRQ_UART,
IRQ_VIRTIO_KBD, IRQ_VIRTIO_NET, IRQ_VIRTIO_GPU, IRQ_VIRTIO_BLK,
IRQ_PLIC_OTHER.

### Channels — Per-Channel Statistics

Returns a table of all active (and recently closed) channels with queue
depths, reference counts, and cumulative message/byte counters per side.

**Request:** `SysinfoCommand::Channels {}`

**Response:** Chunked text (see [Response Format](#response-format)).

### SchedLatency — Scheduler Latency Histogram

Returns a log2 histogram of scheduler runqueue latency (time from enqueue
to dequeue, in microseconds at 10 MHz clock).

**Request:** `SysinfoCommand::SchedLatency {}`

**Response:** Chunked text (see [Response Format](#response-format)).

### IpcLatency — IPC Delivery Latency Histogram

Returns a log2 histogram of IPC message delivery latency (time from
`channel_send` to `channel_recv`, in microseconds at 10 MHz clock).

**Request:** `SysinfoCommand::IpcLatency {}`

**Response:** Chunked text (see [Response Format](#response-format)).

---

## Response Format

All commands use the same chunked response format:

1. The server sends one or more `Message` structs, each containing up to
   `MAX_MSG_SIZE` (1024) bytes of text payload in `msg.data[0..msg.len]`.
2. A **sentinel message** with `msg.len = 0` marks the end of the response.
3. The client should read messages in a loop via `SYS_CHAN_RECV_BLOCKING`
   until it receives the zero-length sentinel.

```rust
loop {
    sys_chan_recv_blocking(sysinfo_handle, &mut resp);
    if resp.len == 0 { break; }  // sentinel
    // process resp.data[..resp.len]
}
```

No capabilities are transferred in sysinfo responses (`msg.cap = NO_CAP`).

---

## Connection Lifecycle

1. Send `BootRequest::ConnectService { name: "sysinfo" }` on handle 0 to get a sysinfo channel.
2. Send exactly **one** command on the sysinfo channel.
3. Read the chunked response until the zero-length sentinel.
4. Close the sysinfo handle with `SYS_CHAN_CLOSE`.

The sysinfo service handles one request per connection. To issue another
command, request a new sysinfo channel from the init server.

---

## Error Handling

If an unrecognized command is sent, the service responds with:

```
"Unknown command\n"
```

followed by the zero-length sentinel.
