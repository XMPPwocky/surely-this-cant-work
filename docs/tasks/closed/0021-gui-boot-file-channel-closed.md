# 0021: GUI programs (window-srv, fbcon) fail to load at boot — file channel closed

**Reported:** 2026-02-24
**Status:** Closed (2026-02-24)
**Severity:** HIGH
**Subsystem:** ext2-server

## Symptoms

When booting with GPU enabled (`qemu_boot gpu=true`), the init server fails
to load `window-server` and `fbcon` from the ext2 filesystem. The boot log
shows:

```
[init] fs: file channel closed for window-srv
[init] fs: file channel closed for fbcon
[init] Loaded net-stack from fs (231568 bytes)
```

The GPU framebuffer is initialized (1280x800) but the display is black
because the window server and framebuffer console never start. The serial
shell works fine. `net-stack` (the last program in the boot list) loads
successfully but then dies because no network device is present.

## Reproduction Steps

1. `make build`
2. Boot with GPU via MCP: `qemu_boot(project_root=..., gpu=true, wait_for_prompt=true)`
3. Observe boot log: "file channel closed" for window-srv and fbcon
4. `qemu_screenshot` shows black screen

## Root Cause

**Bug class:** Protocol mismatch / resource clobbering

The VFS `fs` server (user/fs) uses a **single shared backend channel** per
mount to communicate with the ext2-server. When init requests three file
loads at boot (`window-server`, `fbcon`, `net-stack`), the VFS forwards all
three Open requests sequentially through this single backend channel via
`forward_open()` → `rpc_call()` (blocking RPC).

From ext2-server's perspective, all three Opens arrive on the **same client
connection**. But ext2-server only supports **one open file per client**
(`ClientState.file_ch: Option<Channel<...>>`). Each `do_open()` call invokes
`close_client_file()` which drops the previous file channel before creating
a new one.

**Timeline:**

1. VFS forwards Open for `/bin/window-server` → ext2-bin creates file channel
   A, stores as `client.file_ch`, sends endpoint A_b back
2. VFS forwards Open for `/bin/fbcon` → ext2-bin calls `close_client_file()`
   → **closes file channel A** (ext2-bin's endpoint dropped, channel
   deactivated) → creates channel B, sends B_b back
3. VFS forwards Open for `/bin/net-stack` → ext2-bin **closes channel B** →
   creates channel C, sends C_b back
4. Init runs and tries to read from all three file channels:
   - A_b (window-server): `channel_is_active()` returns false → "file channel closed"
   - B_b (fbcon): same → "file channel closed"
   - C_b (net-stack): still alive → loads successfully (231568 bytes)

The last file opened always succeeds; all previous ones are clobbered.

## Fix

Replaced the per-client `file_ch: Option<Channel>` in ext2-server with a
flat `[Option<FileSlot>; MAX_OPEN_FILES]` array that is independent of
client state. `ClientState` now only tracks the control channel.

- `do_open()` finds a free slot in the flat array instead of clobbering
  the per-client file channel. No previous file channel is closed.
- The main event loop polls all file slots independently of clients.
- Poll registration includes all file slots for blocking.

This allows multiple concurrent open files regardless of which client
connection they arrived through.

## Verification

- `make clippy-user`: clean (no warnings)
- `make test-quick`: 69 passed, 0 failed
- `make test`: 82 passed, 0 failed (12 pre-existing leak warnings)
- GPU boot via MCP: all three programs load successfully:
  ```
  [init] Loaded window-srv from fs (190128 bytes)
  [init] Loaded fbcon from fs (239624 bytes)
  [init] Loaded net-stack from fs (231568 bytes)
  ```
- `qemu_screenshot`: fbcon terminal visible with shell prompt

## Lessons Learned

**Blast radius:** The VFS `fs` server (user/fs) has the same structural
pattern — `file_ch: Option<Channel>` per client. For mounted paths it uses
`forward_open` which bypasses the per-client file_ch, so this bug doesn't
manifest there currently. But for the in-memory tmpfs paths, a client
opening two files would hit the same clobbering. The VFS should be migrated
to the same flat file slot model.

**Prevention:** A test that opens two files concurrently through the same
client connection would catch this. The existing ktest suite only tests
single-file operations.

**Design insight:** Tying open-file state to the client that opened it is
an unnecessary coupling. File channels are independent bidirectional
connections — they don't need to know which control channel created them.
A flat pool of file slots is simpler and more correct.
