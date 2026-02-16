# 0007: Debugger second attach hangs after detach

**Reported:** 2026-02-16
**Status:** Closed (2026-02-16)
**Severity:** HIGH
**Subsystem:** services/proc_debug, ipc

## Symptoms

After attaching the debugger to a process, detaching, and then attempting to
attach to a different process, the second `attach` command hangs indefinitely.
This persists even if the debugger is quit and a new instance is started —
the new debugger's `attach` also hangs.

## Reproduction Steps

1. Boot the system: `make run`
2. Start the debugger: `dbg`
3. Attach to a running process: `attach <pid1>`
4. Detach: `detach`
5. Attach to a different process: `attach <pid2>`
6. Observe: the attach command hangs forever.

Alternative reproduction (new debugger instance):
1-4. Same as above.
5. Quit the debugger: `quit`
6. Start a new debugger: `dbg`
7. Attach to any process: `attach <pid2>`
8. Observe: the attach command hangs forever.

## Root Cause

**Mechanism:** The debug service (`proc_debug_service`) creates two channel
pairs for each debug session — a session channel and an event channel. It
sends the B endpoints (`session_b`, `event_b`) to the debugger client as
capabilities in the attach response. Per the kernel's cap transfer convention,
it calls `channel_inc_ref()` on each endpoint before sending, bringing their
ref counts from 1 to 2.

However, after the send succeeds, the service never closes its own references
to `session_b` and `event_b`. The service only uses `session_a` and `event_a`
going forward, but the B endpoints retain ref_count_b = 2.

When the debugger detaches and closes its handle to `session_b`, the ref count
decrements from 2 to 1. Since ref_count_b > 0, the channel is NOT deactivated
(per `channel_close` at ipc/mod.rs:500-502). The service's
`channel_recv_blocking(session_a)` in `handle_debug_session` never returns
`None`, so the service stays blocked forever. Since the debug service is
single-threaded, it can never accept new connections.

**Fundamental cause:** Missing `channel_close()` for transferred capabilities.
When a kernel service creates a channel pair and sends one endpoint to a client
via cap transfer, it must close its own reference to the sent endpoint after
the send, since it has transferred ownership. The `channel_inc_ref` before the
send creates a second reference for the receiver; the original reference from
`channel_create_pair` must still be closed by the creator.

**Code location:** `kernel/src/services/proc_debug.rs:155-173` — session_b
and event_b are inc_ref'd and sent but never closed on the success path.
(Note: the error path at line 162-168 correctly closes both.)

**Bug class:** Resource leak (reference count leak preventing channel
deactivation, causing deadlock)

## Fix

Add `channel_close(session_b)` and `channel_close(event_b)` after the
successful send of the attach response, before entering the session loop.
This drops the service's original references, leaving only the client's
references. When the client closes its handles (detach or process exit),
the ref counts reach 0, the channels deactivate, `channel_recv_blocking`
returns `None`, and the service returns to `accept_client`.

## Verification

1. `make clippy-kernel` — clean, no warnings.
2. `make build` — success.
3. Boot test — system boots and reaches shell prompt.
4. Attach to PID 6 (fs), detach, re-attach to PID 6 — second attach succeeds.
5. Attach to PID 6, quit debugger, start new debugger instance, attach to
   PID 6 — attach from new instance succeeds.

## Lessons Learned

### 1. Blast Radius
Any kernel service that creates a channel pair and sends one endpoint as a cap
is susceptible to this same leak. Grepped for `channel_create_pair` followed by
`channel_inc_ref` + `channel_send_blocking` — the debug service is the only
kernel service that does this ad-hoc cap transfer (other services use
`KernelTransport` or `send_ok_with_cap` which handle it internally).

### 2. Prevention
The pattern "inc_ref before send, close after send" for transferred endpoints
is error-prone. The error path (send failure) correctly closed both endpoints,
but the success path forgot. A helper function like
`send_and_transfer_endpoint()` that atomically inc_refs, sends, and closes the
sender's reference would make this bug class impossible.

### 3. Invariants
When a kernel service creates a channel pair and transfers one endpoint to a
client via cap, it MUST close its own reference to the transferred endpoint
after the send succeeds. The `channel_inc_ref` before the send creates a
reference for the receiver; the original reference from `channel_create_pair`
remains owned by the creator and must be explicitly closed.

### 4. Memory & Documentation
Added entry to MEMORY.md. The existing "Cap transfer ref counting" invariant
in CLAUDE.md covers the inc_ref requirement but doesn't mention the
corresponding close needed for transferred endpoints. This is a subtlety
worth documenting.

### 5. Debug Tooling
A channel ref-count inspector (shell command or kernel debug print) would have
made this faster to diagnose. Something like `chan <ep>` that shows ref_count_a,
ref_count_b, and blocked PIDs.

### 6. Escalation Notes
This is a standard ref-counting bug — not in "Opus territory" (no page tables,
traps, or scheduling races). Any agent-level model can handle this class.
