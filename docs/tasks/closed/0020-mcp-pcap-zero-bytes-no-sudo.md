# 0020: MCP server pcap capture always reports 0 bytes — tcpdump launched without sudo

**Reported:** 2026-02-24
**Status:** Closed
**Severity:** MEDIUM
**Subsystem:** scripts/qemu-mcp

## Symptoms

The MCP server's `qemu_pcap_start` / `qemu_pcap_stop` tools always report
`"size_bytes": "0"` even when packets are confirmed to be flowing on the bridge
interface. Direct invocation of `tcpdump -i rvos-br0` on the host captures
packets correctly.

Example: during internet connectivity testing, `qemu_pcap_start` was called with
`filter="udp port 53"`. A concurrent manual `tcpdump -i rvos-br0` showed DNS
packets (`10.0.2.75.0 > 10.0.2.2.53: 4660+ A? example.com.`), but
`qemu_pcap_stop` returned:

```json
{
  "path": "/tmp/rvos-XXXXXXXX.pcap",
  "size_bytes": "0"
}
```

## Reproduction Steps

1. Boot QEMU with networking:
   `qemu_boot(project_root="...", network=True)`
2. Start pcap capture:
   `qemu_pcap_start(interface="rvos-br0", filter="udp port 53")`
3. Generate network traffic from within the guest (e.g., DNS lookup via
   `net dns example.com`)
4. Stop capture:
   `qemu_pcap_stop()`
5. Observe `"size_bytes": "0"` in the result.
6. Meanwhile, running `sudo tcpdump -i rvos-br0 udp port 53` directly on the
   host shows packets being captured.

## Root Cause

Two bugs in `scripts/qemu-mcp/server.py`:

### 1. Missing `sudo` — tcpdump cannot capture (primary cause)

At line 459, `pcap_start()` builds the tcpdump command:

```python
cmd = ["tcpdump", "-i", interface, "-w", self.pcap_file, "-U"]
```

This launches tcpdump **without `sudo`**. Capturing packets on a network
interface requires root privileges (or `CAP_NET_RAW` + `CAP_NET_ADMIN`
capabilities on the tcpdump binary). Without privileges, tcpdump fails
immediately with an error like:

```
tcpdump: rvos-br0: You don't have permission to capture on that device
(socket: Operation not permitted)
```

The MCP server process runs as a regular user. Other privileged network
operations in the same file (TAP device creation at lines 214-226) correctly
use `sudo`, but `pcap_start()` does not.

### 2. Silent error suppression — failure is invisible

At lines 463-467:

```python
self.pcap_proc = subprocess.Popen(
    cmd,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
```

Both stdout and stderr are sent to `/dev/null`. When tcpdump fails due to
insufficient privileges, its error message is silently discarded. The
`Popen` object is stored as `self.pcap_proc`, and `pcap_start()` returns
a success message even though tcpdump has already exited with an error.

When `pcap_stop()` is later called:
- `self.pcap_proc.terminate()` sends SIGTERM to a dead process (harmless)
- `self.pcap_proc.wait()` returns immediately (process already exited)
- `os.path.getsize(pcap_path)` returns 0 because tcpdump never wrote data
- No error is reported

**Code locations:**
- `scripts/qemu-mcp/server.py:459` — tcpdump command without sudo
- `scripts/qemu-mcp/server.py:463-467` — Popen with stderr=DEVNULL
- `scripts/qemu-mcp/server.py:470-489` — pcap_stop with no error checking

**Bug class:** Silent failure (privilege error silently discarded, success
reported to caller)

## Fix

Two changes needed:

1. **Add `sudo` to the tcpdump command** (line 459):
   ```python
   cmd = ["sudo", "tcpdump", "-i", interface, "-w", self.pcap_file, "-U"]
   ```
   This matches the pattern already used for TAP device creation in
   `boot()` (lines 214-226).

2. **Capture stderr and check for early exit** in `pcap_start()`:
   After starting the process, wait briefly and check if tcpdump is still
   running. If it exited immediately, read stderr and report the error to
   the caller instead of returning a false success message.

3. **Check return code in `pcap_stop()`**: After terminating tcpdump,
   check `self.pcap_proc.returncode`. If it indicates an error and the
   pcap file is empty, include a warning in the returned result.

## Verification

- Syntax check passes (`py_compile`).
- The `sudo` prefix matches the pattern used for TAP device creation in
  the same file (lines 214-226).
- Early exit detection: after `Popen`, `wait(timeout=0.5)` catches
  immediate failures (permission denied, bad interface) and raises
  `RuntimeError` with the stderr output instead of silently succeeding.
- `pcap_stop()` reads stderr and returncode after termination, and
  includes a warning in the result dict if the pcap file is empty and
  tcpdump exited with an unexpected error code (not 0 or -15/SIGTERM).

## Lessons Learned

- Any subprocess that requires elevated privileges should use `sudo`,
  matching the existing pattern in the same file.
- Never send stderr to DEVNULL for a subprocess that might fail silently.
  Capture stderr via `subprocess.PIPE` and check for early exit to
  surface errors to the caller.
