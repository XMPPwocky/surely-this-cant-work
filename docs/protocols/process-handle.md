# Process Handle Protocol

A process handle is a unidirectional notification channel returned by a Spawn
request on the [boot channel](boot-channel.md). The holder can block on it to
wait for the process to exit.

## Architecture

The process handle is **not** a direct kernel-to-watcher channel. Instead:

1. The kernel sends the exit notification to **init** (via `exit_notify_ep`)
2. Init forwards the notification to all registered watchers
3. This allows multiple watchers per process in the future

```
  kernel ──exit_notify──► init ──watcher_ep──► shell
                               ──watcher_ep──► (future: other watchers)
```

## Wire Format

All messages use `rvos-wire` serialization.

### ExitNotification (init → watcher)

| Field       | Type   | Description                     |
|-------------|--------|---------------------------------|
| exit_code   | `i32`  | Process exit code (0 = success) |

A single message is sent when the process exits, then the channel is closed
from both sides.

## Lifecycle

1. Client sends `Spawn` on boot channel
2. Init loads ELF, spawns process, creates:
   - `(init_notify_ep, kernel_ep)` — kernel notification pair
   - `(client_handle_ep, init_watcher_ep)` — watcher pair
3. Init sets `exit_notify_ep = kernel_ep` on the new process
4. Init records `(init_notify_ep, init_watcher_ep)` in its dynamic spawn table
5. Init sends `Ok` response with `cap = client_handle_ep` to the client
6. Client blocks on `client_handle_ep` via `recv_blocking`
7. Process exits → kernel sends `i32(exit_code)` on `kernel_ep`
8. Init receives on `init_notify_ep`, forwards `i32(exit_code)` on `init_watcher_ep`
9. Init closes both `init_notify_ep` and `init_watcher_ep`
10. Client receives exit notification, closes `client_handle_ep`

## Example

```
# Shell runs: run /bin/hello-std

Shell → init (boot channel):  u8(1) + str("/bin/hello-std")
Init  → shell (boot channel): u8(0), cap=<process handle>

# ... hello-std runs and eventually calls sys_exit ...

Kernel → init (notify channel): i32(0)
Init   → shell (process handle): i32(0)

# Shell prints: "Process exited with code 0"
```
