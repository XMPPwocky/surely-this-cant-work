# Filesystem Protocol

This document specifies the IPC protocol between user-mode clients and the
filesystem server (`fs`). All messages use `rvos-wire` serialization over
standard rvOS IPC channels.

---

## Overview

The filesystem provides a hierarchical namespace of files organized into
directories, accessed via slash-separated absolute paths (e.g. `/etc/motd`).

Interaction uses two kinds of channels:

1. **Control channel** — obtained via service discovery (`"fs"`). Used to open,
   create, and delete files. A single control channel is shared across the
   lifetime of a client's connection to the filesystem server.

2. **File channels** — one per open file, returned by the server as a
   capability in the response to an `Open` request. Read and write operations
   are performed on file channels. The client closes the file by closing the
   channel handle (`sys_chan_close`).

```
  Client                        FS Server
    |                               |
    |--- Open("/etc/motd", 0) ----->|
    |<-- Ok { cap: file_handle } ---|
    |                               |
    |=== file_handle channel ======>|
    |--- Read { off:0, len:64 } --->|
    |<-- Data { bytes } ------------|
    |<-- Data { bytes } ------------|
    |<-- Data { len: 0 } ---------- |  (end of stream)
    |                               |
    |--- sys_chan_close(file_h) ---->|
    |                               |
    |--- Delete("/tmp/old") ------->|  (back on control channel)
    |<-- Ok ------------------------|
```

---

## Service Discovery

Clients request the filesystem service from the init server on handle 0:

```
send(handle_0, Message { data: "fs", len: 2 })
recv(handle_0) → Message { cap: fs_control_handle }
```

All subsequent control-channel operations use `fs_control_handle`.

---

## Control Channel Protocol

### Request (client → server)

| Tag | Name      | Fields                          |
|-----|-----------|---------------------------------|
| `0` | `Open`    | `flags: u8`, `path: str`        |
| `1` | `Delete`  | `path: str`                     |
| `2` | `Stat`    | `path: str`                     |
| `3` | `Readdir` | `path: str`                     |

### Response (server → client)

| Tag | Name    | Fields              | Notes                                      |
|-----|---------|---------------------|--------------------------------------------|
| `0` | `Ok`    | _(none)_            | `msg.cap` carries file handle for `Open`   |
| `1` | `Error` | `code: u8`          | See [Error Codes](#error-codes)            |

### Open

Opens an existing file or creates a new one. The server creates a new channel
pair, installs one endpoint internally, and sends the other back as a
capability in the `Ok` response.

**Flags** (bitfield):

| Bit | Name       | Meaning                                                     |
|-----|------------|-------------------------------------------------------------|
| 0   | `CREATE`   | Create the file if it does not exist                        |
| 1   | `TRUNCATE` | If the file exists, truncate its contents to zero length    |
| 2   | `EXCL`     | Combined with `CREATE`: fail if the file already exists     |

Flag constants:

```
OPEN       = 0x00   // open existing file, fail if absent
CREATE     = 0x01   // create if absent, open if present
TRUNCATE   = 0x02   // truncate existing contents
CREATE_NEW = 0x05   // CREATE | EXCL — fail if file already exists
```

Intermediate directories in the path are created automatically (like
`mkdir -p`) when `CREATE` is set.

**Wire format:**

```
Byte  Type   Field
0     u8     tag = 0
1     u8     flags
2..   str    path  (u16-LE length prefix + UTF-8 bytes)
```

### Delete

Removes a file. Fails if the path does not exist or names a non-empty
directory. Existing file channels for a deleted file remain valid until closed;
they continue to operate on the in-memory contents.

**Wire format:**

```
Byte  Type   Field
0     u8     tag = 1
1..   str    path  (u16-LE length prefix + UTF-8 bytes)
```

### Stat

Returns metadata for a path (file or directory). No file handle is opened.

**Request wire format:**

```
Byte  Type   Field
0     u8     tag = 2
1..   str    path  (u16-LE length prefix + UTF-8 bytes)
```

**Response wire format (Ok):**

```
Byte  Type   Field
0     u8     tag = 0
1     u8     kind  (0 = file, 1 = directory)
2..9  u64    size  (little-endian; bytes for files, 0 for directories)
```

`msg.cap` is `NO_CAP` — no file handle returned.

On error, returns the standard `Error` response (tag=1).

### Readdir

Lists directory entries. The server sends a sequence of entry messages
followed by a sentinel.

**Request wire format:**

```
Byte  Type   Field
0     u8     tag = 3
1..   str    path  (u16-LE length prefix + UTF-8 bytes)
```

**Entry response:**

```
Byte  Type   Field
0     u8     tag = 0 (Entry)
1     u8     kind  (0 = file, 1 = directory)
2..9  u64    size  (little-endian)
10..  str    name  (u16-LE length prefix + UTF-8 bytes)
```

**Sentinel (end of listing):**

```
Byte  Type   Field
0     u8     tag = 0 (Entry)
1     u8     kind = 0xFF (sentinel marker)
```

On error (e.g. path not found, path is not a directory), returns the
standard `Error` response (tag=1).

### Control Response Wire Format

**Ok:**

```
Byte  Type   Field
0     u8     tag = 0
```

The `msg.cap` field carries the file channel handle (for `Open` responses).
For `Delete` responses, `msg.cap` is `NO_CAP`.

**Error:**

```
Byte  Type   Field
0     u8     tag = 1
1     u8     error code
```

---

## File Channel Protocol

Once a client holds a file channel handle from a successful `Open`, it sends
read/write requests on that channel. The server tracks the file identity
internally — the client never resends the path.

### Request (client → server)

| Tag | Name    | Fields                          |
|-----|---------|---------------------------------|
| `0` | `Read`  | `offset: u64`, `len: u32`       |
| `1` | `Write` | `offset: u64`, `data: bytes`    |

### Response (server → client)

| Tag | Name    | Fields              | Notes                              |
|-----|---------|---------------------|------------------------------------|
| `0` | `Data`  | `payload: bytes`    | One or more chunks; see below      |
| `1` | `Ok`    | `written: u32`      | Bytes successfully written         |
| `2` | `Error` | `code: u8`          | See [Error Codes](#error-codes)    |

### Read

Reads up to `len` bytes starting at byte `offset` in the file. The response is
a sequence of one or more `Data` messages followed by a **sentinel** (a `Data`
message with zero-length payload).

If `offset` is at or past end-of-file, the server immediately sends the
zero-length sentinel.

Each `Data` message carries up to **61 bytes** of payload (64-byte message
limit minus tag, length prefix, and alignment).

**Request wire format:**

```
Byte  Type   Field
0     u8     tag = 0
1..8  u64    offset  (little-endian)
9..12 u32    len     (little-endian)
```

Total: 13 bytes.

**Response wire format (Data):**

```
Byte  Type   Field
0     u8     tag = 0
1..   bytes  payload  (u16-LE length prefix + data)
```

End-of-read sentinel: tag `0`, followed by `u16` length `0` (3 bytes total).

### Write

Writes `data` to the file starting at byte `offset`. If `offset` is past the
current end-of-file, the gap is zero-filled. The file grows as needed.

A single write request carries up to **53 bytes** of data (64 minus tag,
offset, and length prefix). To write more data, the client sends multiple
write requests with advancing offsets.

**Request wire format:**

```
Byte  Type   Field
0     u8     tag = 1
1..8  u64    offset  (little-endian)
9..   bytes  data    (u16-LE length prefix + data)
```

**Response wire format (Ok):**

```
Byte  Type   Field
0     u8     tag = 1
1..4  u32    written  (little-endian, bytes actually written)
```

Total: 5 bytes.

### Closing a File

The client closes a file by calling `sys_chan_close` on the file channel
handle. There is no explicit close message. The server detects the closed
endpoint and frees its internal state for that file.

---

## Error Codes

| Code | Name              | Meaning                                           |
|------|-------------------|---------------------------------------------------|
| `1`  | `NotFound`        | Path does not exist (and `CREATE` was not set)     |
| `2`  | `AlreadyExists`   | File exists and `EXCL` was set                     |
| `3`  | `NotAFile`        | Path names a directory where a file was expected   |
| `4`  | `NotEmpty`        | Delete on a non-empty directory                    |
| `5`  | `InvalidPath`     | Path is malformed (empty, not absolute, too long)  |
| `6`  | `NoSpace`         | Filesystem storage exhausted                       |
| `7`  | `Io`              | Unspecified internal error                         |

---

## Path Rules

- Paths are absolute, starting with `/`. The server rejects relative paths
  with `InvalidPath`.
- Path components are separated by `/`. Trailing slashes are ignored.
- `.` and `..` are not supported and treated as literal component names.
- Maximum encoded path length: **60 bytes** (must fit in a 64-byte message
  with tag and flags). Longer paths are rejected with `InvalidPath`.
- Component names may contain any UTF-8 except `/` and the null byte.

---

## Serialization Reference

All fields use `rvos-wire` encoding:

| Type    | Encoding                                      |
|---------|-----------------------------------------------|
| `u8`    | 1 byte                                        |
| `u32`   | 4 bytes, little-endian                         |
| `u64`   | 8 bytes, little-endian                         |
| `str`   | `u16-LE` length prefix, then UTF-8 bytes       |
| `bytes` | `u16-LE` length prefix, then raw bytes          |

Request tag byte is always the first byte of `msg.data`. The kernel-set
`msg.sender_pid` field identifies the caller. Capability handles are carried in
`msg.cap` (set to `NO_CAP` when unused).

---

## Example: Read a File

```rust
// 1. Connect to filesystem server
let fs = request_service(b"fs");

// 2. Open /etc/motd
let mut msg = Message::new();
let mut w = Writer::new(&mut msg.data);
w.write_u8(0)?;          // tag: Open
w.write_u8(0x00)?;       // flags: plain open
w.write_str("/etc/motd")?;
msg.len = w.position();
sys_chan_send(fs, &msg);

// 3. Receive file handle
let mut resp = Message::new();
sys_chan_recv_blocking(fs, &mut resp);
let mut r = Reader::new(&resp.data[..resp.len]);
let tag = r.read_u8()?;
assert!(tag == 0);        // Ok
let file = resp.cap;      // file channel handle

// 4. Read first 128 bytes
let mut w = Writer::new(&mut msg.data);
w.write_u8(0)?;           // tag: Read
w.write_u64(0)?;          // offset
w.write_u32(128)?;        // len
msg.len = w.position();
msg.cap = NO_CAP;
sys_chan_send(file, &msg);

// 5. Collect data chunks
let mut buf = [0u8; 128];
let mut pos = 0;
loop {
    sys_chan_recv_blocking(file, &mut resp);
    let mut r = Reader::new(&resp.data[..resp.len]);
    let tag = r.read_u8()?;
    assert!(tag == 0);     // Data
    let chunk = r.read_bytes()?;
    if chunk.is_empty() { break; }  // sentinel
    buf[pos..pos + chunk.len()].copy_from_slice(chunk);
    pos += chunk.len();
}

// 6. Close file
sys_chan_close(file);
```

## Example: Create and Write a File

```rust
// Open (creating if needed) /tmp/greeting
let mut w = Writer::new(&mut msg.data);
w.write_u8(0)?;           // tag: Open
w.write_u8(0x01)?;        // flags: CREATE
w.write_str("/tmp/greeting")?;
msg.len = w.position();
sys_chan_send(fs, &msg);

sys_chan_recv_blocking(fs, &mut resp);
let file = resp.cap;

// Write "Hello, world!\n" at offset 0
let data = b"Hello, world!\n";
let mut w = Writer::new(&mut msg.data);
w.write_u8(1)?;           // tag: Write
w.write_u64(0)?;          // offset
w.write_bytes(data)?;
msg.len = w.position();
msg.cap = NO_CAP;
sys_chan_send(file, &msg);

sys_chan_recv_blocking(file, &mut resp);
let mut r = Reader::new(&resp.data[..resp.len]);
let tag = r.read_u8()?;
assert!(tag == 1);         // Ok
let written = r.read_u32()?;
assert!(written == 14);

sys_chan_close(file);
```
