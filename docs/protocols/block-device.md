# Block Device Protocol

The **block device** protocol provides sector-level read/write access to
VirtIO block devices via the `blk_server` kernel task. Each block device
gets its own server instance registered as a named service.

Service names: `"blk0"`, `"blk1"`, etc. (one per detected VirtIO block device)

Protocol definition: `lib/rvos-proto/src/blk.rs`

## Connection

1. Connect to a block device service (e.g., `"blk0"`) via the boot channel.
2. Send `GetDeviceInfo` to obtain device parameters and an SHM capability.
3. Use the SHM region for bulk data transfer on subsequent Read/Write requests.

Only one client connection is active at a time. If the client disconnects,
the server accepts a new client.

## Shared Memory

The server allocates a 128 KiB SHM region (32 pages) for bulk data transfer.
The SHM capability is sent as a cap in the first `DeviceInfo` response. The
client maps this SHM and uses it as a data staging area:

- **Read**: server copies sectors from disk into SHM at `shm_offset`, then
  sends `Ok`. Client reads data from SHM.
- **Write**: client writes data into SHM at `shm_offset`, then sends `Write`
  request. Server copies data from SHM to disk.

## Messages

**BlkRequest** (client -> server):

| Tag | Name          | Fields                                    | Description                          |
|-----|---------------|-------------------------------------------|--------------------------------------|
| 0   | GetDeviceInfo |                                           | Request device info + SHM cap        |
| 1   | Read          | `sector: u64, count: u32, shm_offset: u32`| Read sectors into SHM                |
| 2   | Write         | `sector: u64, count: u32, shm_offset: u32`| Write sectors from SHM              |
| 3   | Flush         |                                           | Flush cached writes to stable storage|

**BlkResponse** (server -> client):

| Tag | Name       | Fields                                                            | Description                    |
|-----|------------|-------------------------------------------------------------------|--------------------------------|
| 0   | DeviceInfo | `capacity_sectors: u64, sector_size: u32, read_only: u8, serial: &[u8]` | Device parameters + SHM cap   |
| 1   | Ok         |                                                                   | Operation succeeded            |
| 2   | Error      | `code: u32`                                                       | Operation failed               |

The `DeviceInfo` response carries the SHM capability in `msg.caps[0]`
(first response only; subsequent `GetDeviceInfo` calls omit the cap).

## Error Codes

| Code | Name   | Meaning                                 |
|------|--------|-----------------------------------------|
| 5    | EIO    | I/O error (device operation failed)     |
| 22   | EINVAL | Invalid arguments (bad sector/offset)   |
| 30   | EROFS  | Read-only filesystem (write to RO disk) |

## Usage Pattern

```
GetDeviceInfo        -> DeviceInfo { capacity, sector_size, read_only, serial }
                        (msg.caps[0] = SHM handle)
[map SHM into address space]
Read { sector: 0, count: 1, shm_offset: 0 }  -> Ok
[read 512 bytes from SHM offset 0]
[write data to SHM offset 0]
Write { sector: 0, count: 1, shm_offset: 0 } -> Ok
Flush                -> Ok
[close channel to disconnect]
```

## Constants

Defined in `kernel/src/services/blk_server.rs`:

```
SHM_PAGE_COUNT    = 32     (128 KiB)
MAX_BLK_SERVERS   = 4
SECTOR_SIZE       = 512    (from drivers/virtio/blk.rs)
```
