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

### PS — Process List

Returns a formatted text table of all processes with their PID, state,
CPU usage (1-second and 1-minute EWMA), memory usage, and name.

**Request:**

```
msg.data = "PS"
msg.len  = 2
```

**Response:** Chunked text (see [Response Format](#response-format)).

Example output:

```
  PID  STATE     CPU1s  CPU1m  MEM     NAME
  ---  --------  -----  -----  ------  ----------------
    0  Ready      0.0%   0.0%     0K  idle
    1  Running   12.3%   8.5%   144K  init
    2  Blocked    0.0%   0.1%    16K  serial-con
    3  Ready      0.5%   0.3%    48K  fs
```

**Columns:**

| Column | Description |
|--------|-------------|
| PID    | Process ID (0 = idle task) |
| STATE  | Ready, Running, Blocked, or Dead |
| CPU1s  | CPU usage over a 1-second EWMA window (0.0%–100.0%) |
| CPU1m  | CPU usage over a 1-minute EWMA window (0.0%–100.0%) |
| MEM    | Total physical pages owned, in KiB (pages × 4K) |
| NAME   | Process name (max 16 chars) |

### MEMSTAT — Kernel Memory Statistics

Returns kernel heap statistics (per-tag breakdown) and per-process
physical memory usage.

**Request:**

```
msg.data = "MEMSTAT"
msg.len  = 7
```

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

### TRACE — Read Trace Buffer

Returns the contents of the kernel's trace ring buffer as formatted text.
Each line contains a timestamp, PID, and trace label.

**Request:**

```
msg.data = "TRACE"
msg.len  = 5
```

**Response:** Chunked text (see [Response Format](#response-format)).

### TRACECLR — Clear Trace Buffer

Clears the kernel trace ring buffer and responds with `"ok\n"`.

**Request:**

```
msg.data = "TRACECLR"
msg.len  = 8
```

**Response:** Chunked text containing `"ok\n"`.

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

1. Send a service name `"sysinfo"` on handle 0 to get a sysinfo channel.
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
