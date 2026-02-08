# Boot Channel Protocol

The boot channel is a bidirectional IPC channel pre-installed as handle 0 in every
user process. The other end is held by the init server. It serves two purposes:

1. **Service discovery** — connect to named services (stdio, sysinfo, math, fs, etc.)
2. **Process spawning** — launch a new process from a filesystem path

## Wire Format

All messages use `rvos-wire` serialization.

### Request (client → init)

| Tag | Name             | Payload          | Cap     |
|-----|------------------|------------------|---------|
| 0   | ConnectService   | `str(name)`      | NO_CAP  |
| 1   | Spawn            | `str(path)`      | NO_CAP  |

**ConnectService** requests a connection to a named service. `name` is an ASCII
string like `"stdio"`, `"sysinfo"`, `"math"`, or `"fs"`. Init creates a fresh
channel pair, sends one end to the service's control channel, and returns the
other end to the client.

**Spawn** requests a new user process loaded from `path` (e.g., `"/bin/hello-std"`).
Init loads the ELF from the filesystem, spawns the process, and returns a process
handle channel the client can wait on.

### Response (init → client)

| Tag | Name   | Payload          | Cap                          |
|-----|--------|------------------|------------------------------|
| 0   | Ok     | (empty)          | service channel or proc handle |
| 1   | Error  | `str(message)`   | NO_CAP                       |

**Ok** indicates success. The `cap` field contains a channel handle:
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
Request:  u8(0) + str("sysinfo")     → tag=ConnectService, name="sysinfo"
Response: u8(0)                        → tag=Ok, cap=<sysinfo channel handle>
```

### Spawn a process

```
Request:  u8(1) + str("/bin/hello-std") → tag=Spawn, path="/bin/hello-std"
Response: u8(0)                          → tag=Ok, cap=<process handle channel>
```

### Spawn error

```
Request:  u8(1) + str("/bin/nonexistent")
Response: u8(1) + str("not found")       → tag=Error
```
