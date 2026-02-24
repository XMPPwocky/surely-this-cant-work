# 0002: GUI shell stops responding after child process exits

**Reported:** 2026-02-10
**Status:** Closed (2026-02-10)
**Severity:** HIGH
**Subsystem:** init, ipc

## Symptoms

When running a program (e.g., `/bin/hello-std`) from the fbcon GUI shell,
the program executes successfully but the shell becomes permanently
unresponsive afterward. No further commands can be entered or output
displayed. This does NOT happen through the serial console.

Started happening after commit a33a409 (Propagate namespace overrides from
parent to child processes).

## Reproduction Steps

1. `make run-gui`
2. In the fbcon GUI shell, type: `run /bin/hello-std`
3. hello-std runs and prints output
4. Shell never prints another prompt; keyboard input is ignored

## Investigation

The user reported the bug with a key clue: "this started happening after the recent change to
inherit namespace overrides." The first step was to identify the offending commit.

**Step 1: Identify the regression commit.** `git log --oneline -10` confirmed that commit
`a33a409` ("Propagate namespace overrides from parent to child processes"), merged minutes
before the bug was reported, was the immediate suspect. `git diff a33a409^..a33a409` was read
to understand what changed. The commit added `merge_overrides` to copy parent namespace
overrides into child boot registrations during `handle_spawn_request`.

**Step 2: Read hello-std source to understand its behavior.** A subagent read
`user/hello/src/main.rs` to confirm that hello-std uses `println!`/`print!` (stdout) and
calls filesystem services, meaning it connects to the override channels inherited from the GUI
shell.

**Step 3: Investigate the cap transfer mechanism.** Two parallel subagents searched the
kernel IPC subsystem:
- One looked for `encode_cap_channel`/`decode_cap_channel` and how caps are transferred
  during message delivery. This revealed `KernelTransport::send` in
  `kernel/src/ipc/transport.rs`, which calls `ipc::encode_cap_channel(cap)` and then
  `ipc::channel_send_blocking` — without calling `channel_inc_ref`.
- Another searched for process exit and handle cleanup logic, discovering
  `terminate_current_process` in `kernel/src/task/scheduler.rs`, which iterates all handles
  and calls `channel_close(ep)` for each `HandleObject::Channel`.

**Step 4: Find the ref counting invariant.** The IPC code in `kernel/src/ipc/mod.rs` showed
that `Channel::new()` initializes `ref_count_a = 1, ref_count_b = 1`, and that
`channel_close` decrements the ref count and deactivates the channel when it reaches zero.
The function `channel_inc_ref` exists to increment the count when sharing an endpoint.

**Step 5: Trace the user-space syscall path for comparison.** `translate_cap_for_send` in
`kernel/src/arch/trap.rs` was identified as the correct pattern: it calls `channel_inc_ref`
for every cap placed in a message's `caps[]` array. The kernel init server's direct calls to
`channel_send_blocking` skip this step entirely.

**Root cause identified (line ~105 of the session, ~8 minutes after bug report):** The agent
concluded that when init sends a namespace override cap to the shell (and then to hello-std)
without incrementing the ref count, all three entities share the same endpoint at ref count 1.
When hello-std exits and closes its handles, `channel_close` decrements the count to 0 and
deactivates the channel, killing the shell's stdin/stdout. The serial console was unaffected
because serial console processes do not receive namespace overrides for stdin/stdout.

No dead ends or false hypotheses were recorded — the initial clue ("started after the NS
override commit") pointed directly to the affected code path, and the investigation proceeded
linearly through code reading.

## Root Cause

**Mechanism:** The init server (a kernel task) sends IPC messages with
capability channels by calling `ipc::channel_send_blocking` directly,
bypassing the user-space syscall path (`sys_chan_send` → `translate_cap_for_send`).
The syscall path calls `channel_inc_ref()` for each cap being transferred;
the kernel-internal path does not.

When fbcon spawns the shell with namespace overrides for stdin/stdout, the
override endpoints are stored in the shell's boot registration with a ref
count of 1. When the shell asks init for "stdin", init sends the override
endpoint as a cap — without incrementing the ref count. The shell receives
a handle, but the ref count is still 1.

When the shell spawns hello-std, the namespace overrides are inherited
(copied to hello-std's boot registration). hello-std also connects to
"stdin" and "stdout" using the same override endpoints — again without ref
count increments. Now three entities reference each endpoint (init's
override, shell's handle, hello-std's handle), but the ref count is still 1.

When hello-std exits, `terminate_current_process` closes all its handles.
`channel_close(ep)` decrements the ref count from 1 to 0, deactivating the
channel. The shell's stdin/stdout connections to fbcon are now dead.

**Fundamental cause:** The kernel init server bypasses the cap-transfer ref
counting that user-process syscalls perform. This is a protocol error: any
code path that places a cap in a message must increment the ref count.

**Code location:** `kernel/src/services/init.rs` (sends override cap
without inc_ref), `kernel/src/arch/trap.rs` (`translate_cap_for_send` is
the correct pattern, but only runs in the syscall path).

**Bug class:** Protocol error (ref count invariant violation)

## Fix

Three changes to `kernel/src/services/init.rs`:

1. **ConnectService handler:** Call `ipc::channel_inc_ref(override_ep)`
   before sending a namespace override cap. This ensures each process that
   receives an override endpoint gets its own ref count.

2. **merge_overrides:** Call `ipc::channel_inc_ref(p.endpoint)` when
   copying a non-removed parent override into the child's boot registration.
   This gives the child's registration its own reference, separate from the
   parent's.

3. **Boot registration cleanup:** When a dead boot registration is removed,
   close all non-removed override endpoints (decrement ref counts) before
   dropping the registration. Endpoints are collected under the config lock
   and closed outside it to avoid lock ordering issues.

## Verification

1. `make build` — no warnings or errors
2. `make run-gui` — system boots, fbcon shell appears
3. `run /bin/hello-std` from GUI shell — program runs, shell returns to
   prompt and accepts further commands
4. Serial console shell continues to work normally

## Lessons Learned

**Invariant:** Any kernel code path that places a capability (endpoint ID)
into a message's `caps[]` array must call `channel_inc_ref()` for that
endpoint. The user-space syscall path (`translate_cap_for_send`) does this
automatically, but kernel tasks calling `channel_send`/`channel_send_blocking`
directly must do it manually. Similarly, any code that stores an endpoint ID
(taking ownership of a reference) must eventually call `channel_close()` to
release it.

**Blast radius:** The same ref-count-missing pattern exists in other init
server send paths (handle_service_request, handle_stdio_request,
finish_fs_launch), but those create fresh channel pairs and give each side
away exactly once, so the initial ref count of 1 happens to be correct.
Only the namespace override path reuses the same endpoint across multiple
sends.
