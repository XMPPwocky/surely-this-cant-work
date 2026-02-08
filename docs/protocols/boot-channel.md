# Boot Channel Protocol

The boot channel is a bidirectional IPC channel pre-installed as handle 0 in every
user process. The other end is held by the init server. It serves two purposes:

1. **Service discovery** — connect to named services (stdio, sysinfo, math, fs, etc.)
2. **Process spawning** — launch a new process from a filesystem path

## Wire Format

All messages use `rvos-wire` serialization. Types are defined in
`rvos-proto::boot`.

### Request (client → init)

```rust
define_message! {
    pub enum BootRequest<'a> {
        ConnectService(0) { name: &'a str },
        Spawn(1) { path: &'a str },
    }
}
```

**ConnectService** requests a connection to a named service. `name` is an ASCII
string like `"stdio"`, `"sysinfo"`, `"math"`, or `"fs"`. Init creates a fresh
channel pair, sends one end to the service's control channel, and returns the
other end to the client.

**Spawn** requests a new user process loaded from `path` (e.g., `"/bin/hello-std"`).
Init loads the ELF from the filesystem, spawns the process, and returns a process
handle channel the client can wait on.

### Response (init → client)

```rust
define_message! {
    pub enum BootResponse<'a> {
        Ok(0) {},
        Error(1) { message: &'a str },
    }
}
```

**Ok** indicates success. The message `cap` field contains a channel handle:
- For ConnectService: the client endpoint of the service channel
- For Spawn: a process handle channel (see [process-handle.md](process-handle.md))

**Error** indicates failure. `message` is a human-readable error string
(e.g., `"not found"`, `"busy"`, `"no fs"`).

## Stdio Special Case

The `"stdio"` service name triggers special handling: init also tells the console
server whether this client is a shell (wants stdin) by sending `data[0] = 1` on
the control message to the console server. From the client's perspective, the
request/response format is identical to any other ConnectService.

## Examples

### Connect to sysinfo

```
Request:  BootRequest::ConnectService { name: "sysinfo" }
Response: BootResponse::Ok {}, cap=<sysinfo channel handle>
```

### Spawn a process

```
Request:  BootRequest::Spawn { path: "/bin/hello-std" }
Response: BootResponse::Ok {}, cap=<process handle channel>
```

### Spawn error

```
Request:  BootRequest::Spawn { path: "/bin/nonexistent" }
Response: BootResponse::Error { message: "not found" }
```
