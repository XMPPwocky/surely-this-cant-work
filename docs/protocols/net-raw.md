# net-raw Protocol

The **net-raw** service is a kernel task (`net_server`) that wraps the VirtIO
net device. A single client (the user-space `net-stack`) connects and
exchanges Ethernet frames via a shared-memory (SHM) ring buffer, using IPC
messages as doorbells.

## Connection Handshake

1. `net-stack` connects to the `"net-raw"` named service.
2. Sends `GetDeviceInfo {}`.
3. Receives `DeviceInfo { mac0..mac5, mtu }` with the SHM capability in
   `msg.caps[0]`.
4. Maps the SHM region via `sys_mmap(cap, SHM_PAGE_COUNT * 4096)`.

## SHM Layout

Total size: **5 pages** (20,480 bytes).

```
Offset  Size   Description
──────  ─────  ────────────────────────────
0x0000  64 B   Control block (4 x u32 indices)
0x0040  12 KB  RX ring (8 slots x 1536 bytes)
0x3040  6 KB   TX ring (4 slots x 1536 bytes)
```

### Control Block (offset 0x0000)

| Offset | Type | Name       | Writer      | Reader      |
|--------|------|------------|-------------|-------------|
| 0x00   | u32  | rx_head    | kernel      | net-stack   |
| 0x04   | u32  | rx_tail    | net-stack   | kernel      |
| 0x08   | u32  | tx_head    | net-stack   | kernel      |
| 0x0C   | u32  | tx_tail    | kernel      | net-stack   |

All indices are monotonically increasing and wrap via modular arithmetic
(`index % SLOTS`). The ring is empty when `head == tail` and full when
`head - tail >= SLOTS`.

### RX Slot Layout (1536 bytes each)

| Offset | Size     | Description              |
|--------|----------|--------------------------|
| 0      | 2 bytes  | Frame length (u16 LE)    |
| 2      | 1534     | Ethernet frame data      |

### TX Slot Layout (1536 bytes each)

Same as RX.

## Memory Ordering

The SHM ring is a single-producer, single-consumer (SPSC) queue for each
direction. The required fence pattern:

- **Producer** (writer): write frame data, then `Release` fence, then
  advance the head index.
- **Consumer** (reader): read head/tail indices, then `Acquire` fence,
  then read frame data.

All index and data accesses use volatile reads/writes (`read_volatile` /
`write_volatile`) since the memory is shared across address spaces.

## Doorbell Messages

IPC messages between kernel and net-stack are lightweight doorbells (no
payload beyond the discriminant tag). The SHM ring is the actual data path.

### net-stack -> kernel (NetRawRequest)

| Tag | Name        | Meaning                                    |
|-----|-------------|--------------------------------------------|
| 0   | GetDeviceInfo | Initial handshake (connection setup)     |
| 1   | TxReady     | New TX frames written to SHM ring          |
| 2   | RxConsumed  | RX frames consumed, slots available        |

### kernel -> net-stack (NetRawResponse)

| Tag | Name        | Meaning                                    |
|-----|-------------|--------------------------------------------|
| 0   | DeviceInfo  | MAC + MTU + SHM cap (handshake response)   |
| 1   | RxReady     | New RX frames available in SHM ring        |
| 2   | TxConsumed  | TX frames consumed, slots available        |

## Constants

Defined in `kernel/src/services/net_server.rs` and mirrored in
`user/net-stack/src/main.rs`:

```
SHM_PAGE_COUNT  = 5
RX_SLOTS        = 8
TX_SLOTS        = 4
RX_SLOT_SIZE    = 1536
TX_SLOT_SIZE    = 1536
RX_RING_OFFSET  = 0x0040
TX_RING_OFFSET  = 0x3040
```

A compile-time assertion in the kernel verifies that the layout fits
within the allocated pages.

## Socket Protocol

Above net-raw sits the **net-stack** user-space process, which provides TCP
and UDP socket APIs to applications via the `"net"` named service. See
`docs/protocols/socket.md` and `lib/rvos-proto/src/socket.rs` for the
full socket protocol definition.
