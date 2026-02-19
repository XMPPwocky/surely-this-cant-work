# Socket Protocol

The **socket** protocol provides BSD-style socket access to user-space
programs via the `net-stack` process. It sits above the `net-raw` kernel
service (see `net-raw.md`) and implements UDP datagram sockets and TCP
stream sockets with full connection management.

Service name: `"net"`

Protocol definition: `lib/rvos-proto/src/socket.rs`

## Architecture

```
  User process           net-stack            kernel (net_server)
  ┌──────────┐      ┌──────────────┐      ┌─────────────────┐
  │ std::net  │      │  TCP/IP      │      │  VirtIO net     │
  │ TcpStream │◄────►│  state       │◄────►│  device driver  │
  │ UdpSocket │      │  machine     │      │                 │
  └──────────┘      └──────────────┘      └─────────────────┘
    IPC channels       SHM ring + IPC        hardware
```

User programs connect to the `"net"` service, create per-socket channels,
and issue socket operations. The net-stack translates these to Ethernet
frames exchanged with the kernel's net-raw service via SHM.

## Two-Layer Protocol

### Layer 1: Sockets Control Channel

Created by connecting to the `"net"` named service. Used only to create
new sockets.

**SocketsRequest** (client → net-stack):

| Tag | Name   | Fields                 | Description            |
|-----|--------|------------------------|------------------------|
| 0   | Socket | `sock_type: SocketType`| Create a new socket    |

**SocketType** variants: `Dgram(0)` (UDP), `Stream(1)` (TCP).

**SocketsResponse** (net-stack → client):

| Tag | Name    | Fields                     | Description               |
|-----|---------|----------------------------|---------------------------|
| 0   | Created | `socket: RawChannelCap`    | Per-socket channel cap    |
| 1   | Error   | `code: SocketError`        | Socket creation failed    |

The `Created` response carries a **per-socket channel capability** in the
message's cap slot. The client uses this channel for all subsequent
operations on that socket.

### Layer 2: Per-Socket Channel

Each socket gets a dedicated IPC channel. The client sends `SocketRequest`
messages and receives either `SocketResponse` (control) or `SocketData`
(data delivery) responses.

**SocketRequest** (client → net-stack):

| Tag | Name        | Fields                          | Description                    |
|-----|-------------|---------------------------------|--------------------------------|
| 0   | Bind        | `addr: SocketAddr`              | Bind to local address          |
| 1   | Listen      | `backlog: u32`                  | Start listening (TCP)          |
| 2   | Accept      |                                 | Accept connection (TCP, blocks)|
| 3   | Connect     | `addr: SocketAddr`              | Connect to remote (TCP)        |
| 4   | Send        | `data: &[u8]`                   | Send data (connected)          |
| 5   | Recv        | `max_len: u32`                  | Receive data (connected)       |
| 6   | SendTo      | `addr: SocketAddr, data: &[u8]` | Send datagram (UDP)            |
| 7   | RecvFrom    |                                 | Receive datagram (UDP)         |
| 8   | Shutdown    | `how: ShutdownHow`              | Shutdown direction(s)          |
| 9   | GetSockName |                                 | Get local address              |
| 10  | GetPeerName |                                 | Get remote address             |

**ShutdownHow** variants: `Read(0)`, `Write(1)`, `Both(2)`.

**SocketResponse** (net-stack → client, control responses):

| Tag | Name     | Fields                                    | Description                |
|-----|----------|-------------------------------------------|----------------------------|
| 0   | Ok       |                                           | Generic success            |
| 1   | Error    | `code: SocketError`                       | Operation failed           |
| 2   | Accepted | `peer_addr: SocketAddr, socket: RawChannelCap` | Accepted connection   |
| 3   | Addr     | `addr: SocketAddr`                        | Address result             |
| 4   | Sent     | `bytes: u32`                              | Send byte count            |

**SocketData** (net-stack → client, data responses):

| Tag | Name     | Fields                          | Description                |
|-----|----------|---------------------------------|----------------------------|
| 0   | Data     | `data: &[u8]`                   | Stream data (Recv)         |
| 1   | Datagram | `addr: SocketAddr, data: &[u8]` | Datagram with sender addr  |

### Response Type by Request

| Request   | Response Type                  |
|-----------|--------------------------------|
| Bind      | `SocketResponse::Ok/Error`     |
| Listen    | `SocketResponse::Ok/Error`     |
| Accept    | `SocketResponse::Accepted/Error` |
| Connect   | `SocketResponse::Ok/Error`     |
| Send      | `SocketResponse::Sent/Error`   |
| Recv      | `SocketData::Data`             |
| SendTo    | `SocketResponse::Sent/Error`   |
| RecvFrom  | `SocketData::Datagram`         |
| Shutdown  | `SocketResponse::Ok/Error`     |
| GetSockName | `SocketResponse::Addr/Error` |
| GetPeerName | `SocketResponse::Addr/Error` |

## Error Codes

**SocketError** variants:

| Code | Name             | Meaning                               |
|------|------------------|---------------------------------------|
| 1    | AddrInUse        | Address/port already bound            |
| 2    | AddrNotAvail     | Address not available                 |
| 3    | ConnRefused      | Connection refused (RST received)     |
| 4    | ConnReset        | Connection reset by peer              |
| 5    | NotConnected     | Socket not connected                  |
| 6    | AlreadyConnected | Socket already connected              |
| 7    | InvalidArg       | Invalid argument                      |
| 8    | TimedOut         | Operation timed out                   |
| 9    | NoResources      | Out of sockets/connections            |
| 10   | NotSupported     | Operation not supported for this type |

## Socket Address

**SocketAddr** currently supports IPv4 only:

```
Inet4 { a: u8, b: u8, c: u8, d: u8, port: u16 }
```

Port 0 in Bind requests means "assign an ephemeral port".

## Socket Lifecycle

### UDP (Dgram)

```
Socket(Dgram) → Created(cap)
Bind(addr)    → Ok
SendTo(addr, data) → Sent { bytes }
RecvFrom      → Datagram { addr, data }
[close channel to clean up]
```

### TCP Client (Stream)

```
Socket(Stream) → Created(cap)
Connect(addr)  → Ok
Send(data)     → Sent { bytes }
Recv(max_len)  → Data { data }
Shutdown(Both) → Ok
[close channel to clean up]
```

### TCP Server (Stream)

```
Socket(Stream) → Created(cap)
Bind(addr)     → Ok
Listen(backlog) → Ok
Accept          → Accepted { peer_addr, socket: cap }
  [use new cap for Send/Recv on accepted connection]
[close listener channel to stop accepting]
```

## RAII Cleanup

Closing the per-socket IPC channel implicitly closes the socket. For TCP
streams, `TcpStream::drop` sends `Shutdown(Both)` before closing the
channel to ensure a clean FIN sequence rather than an abrupt RST.

## Constants

Defined in `user/net-stack/src/main.rs`:

```
MAX_SOCKETS         = 64
MAX_TCP_CONNS       = 64
TCP_ACCEPT_BACKLOG  = 8
TCP_WINDOW          = 8192
TCP_INITIAL_RTO     = 3_000_000  (300ms at 10MHz)
```

## std::net Integration

The Rust `std::net` types (`TcpStream`, `TcpListener`, `UdpSocket`) are
implemented in `vendor/rust/library/std/src/sys/net/connection/rvos/` and
map directly to this protocol. The PAL module handles serialization,
channel lifecycle, and error translation transparently.
