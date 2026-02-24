# 0008: parse_ns_overrides missing inc_ref for redirect endpoints

**Reported:** 2026-02-16
**Status:** Closed (2026-02-16)
**Severity:** HIGH
**Subsystem:** init, ipc

## Symptoms

When a process is spawned with both a capability (extra_cap on handle 1) and
a namespace override that redirects to the same capability, spawning a second
child with the same override panics with:

```
channel_inc_ref: channel 17 is inactive
```

This occurs because the override endpoint was deactivated when the first
child exited.

## Reproduction Steps

1. Create a channel pair (ep_a, ep_b)
2. Spawn child 1 with:
   - extra_cap = ep_b (delivered as handle 1)
   - NsOverride::Redirect("some-service", cap_index=0) pointing to the same ep_b
3. Wait for child 1 to exit
4. Spawn child 2 with the same override endpoint
5. Panic: `channel_inc_ref: channel N is inactive`

Discovered by the `test_two_children_shared_override` regression test.

## Investigation

The bug was discovered incidentally while writing ktest regression tests for
past bugs. The goal was to add a `test_two_children_shared_override` test that
would catch a recurrence of Bug 0002 — spawning two sequential children that
share the same namespace override endpoint.

**Initial test design and first deadlock.** The first test attempt redirected
`hello-std`'s `stdout` service to a raw channel under ktest's control. This
caused a test timeout. Investigation revealed that the rvOS std's `send_write()`
function sends a `FileRequest::Write` message and then blocks waiting for a
`WriteOk` response. When stdout is redirected to a raw channel with no server
on the other end, the child hangs permanently on its first `println!` call,
never exiting.

**First fix attempt: concurrent drain.** A `drain_and_wait` helper was written
to drain the output channel in parallel with waiting for the process exit
notification. This also failed: the child blocked before the ktest side could
start draining — the block happened on the very first write, before the queue
could fill.

**Root cause of the deadlock.** Reading `vendor/rust/library/std/src/sys/stdio/rvos.rs`
confirmed that `send_write()` always awaits `WriteOk`. The redirect was
fundamentally incompatible with the file protocol.

**Workaround enabling further testing.** Instead of redirecting `stdout`, the
tests were changed to redirect a custom service name (`"ktest-svc"`) that
`hello-std` never connects to. This exercised the cap ref-counting path (the
override is stored in the `BootRegistration`) without triggering the file
protocol deadlock.

**Bug discovery.** With the corrected tests, `make test` ran the cap ref
counting section. The first test (`test_ns_override_cap_delivery`) passed.
The second (`test_two_children_shared_override`) triggered a kernel panic:

```
!!! KERNEL PANIC !!!
panicked at kernel/src/ipc/mod.rs:475:5:
channel_inc_ref: channel 17 is inactive
scause:  0x8
stval:   0x0
sepc:    0x203b4
sstatus: 0x200040020
Backtrace:
    #0: ra=0x80203988 fp=0x812651b0
    #1: ra=0x80216140 fp=0x812651f0
    #2: ra=0x8021c112 fp=0x81265220
    #3: ra=0x8020f22e fp=0x81265240
    #4: ra=0x80200104 fp=0x81266000
```

**Root cause identification.** Examining `parse_ns_overrides()` in
`kernel/src/services/init.rs` showed it decoded the cap endpoint from
`message.caps[]` and stored it in `NsOverride.endpoint` with no call to
`channel_inc_ref()`. The IPC transfer path (`translate_cap_for_send`) had
already called `channel_inc_ref` once — but that covered only the `extra_cap`
delivery to handle 1 in the child. The `BootRegistration` storing the override
endpoint was a separate ownership that required its own ref count. When child
1 exited and both its handle 1 and the boot registration cleanup closed the
endpoint, the ref count dropped to zero and the channel deactivated. Spawning
child 2 with the same override then attempted `channel_inc_ref` on an inactive
channel, causing the panic.

## Root Cause

**Mechanism:** When `handle_spawn_request` processes a spawn message containing
a capability and namespace overrides, it:

1. Calls `translate_cap_for_send()` to inc_ref the cap for IPC transfer
   (this creates the handle 1 reference for the child)
2. Calls `parse_ns_overrides()` to decode the override blob and store
   `NsOverride` entries in the child's `BootRegistration`

`parse_ns_overrides()` decoded the cap endpoint from the message's `caps[]`
array and stored it in `NsOverride.endpoint`, but did NOT call
`channel_inc_ref()`. This meant the `BootRegistration` held a reference to
the endpoint without owning a ref count for it.

When the child exits, `terminate_current_process` closes handle 1 (the
extra_cap), decrementing the ref count. Then boot registration cleanup
closes the override endpoint — but the ref count is already 0, so this
either panics or double-frees. More critically, when a second child is
spawned with the same override, `channel_inc_ref` is called on an
already-deactivated channel, causing the panic.

**Fundamental cause:** `parse_ns_overrides()` takes ownership of an endpoint
reference (by storing it in `BootRegistration`) without incrementing the
ref count. The IPC transfer's inc_ref only covers the extra_cap (handle 1)
delivery; the override storage is a separate ownership that needs its own
ref count.

**Code location:** `kernel/src/services/init.rs`, `parse_ns_overrides()`
function, redirect branch.

**Bug class:** Protocol error (ref count invariant violation) — same class
as Bug 0002.

## Fix

In `parse_ns_overrides()`, call `ipc::channel_inc_ref(ep)` after decoding
the endpoint from the cap array, before storing it in the `NsOverride`:

```rust
if let Some(ep) = ipc::decode_cap_channel(encoded) {
    ipc::channel_inc_ref(ep);  // BootRegistration holds its own reference
    result[out_idx] = Some(NsOverride {
        name,
        name_len: nlen,
        endpoint: ep,
        removed: false,
    });
    out_idx += 1;
}
```

This ensures the BootRegistration's override entry has its own ref count,
separate from the IPC transfer's ref count for extra_cap delivery.

## Verification

1. `make clippy` — clean
2. `make build` — success
3. `make test` — all 69 tests pass (55 original + 14 new regression tests)
4. `test_two_children_shared_override` specifically exercises this bug:
   spawns two sequential children with the same override, verifying both
   succeed without panic

## Lessons Learned

**Invariant reinforcement:** Any code that stores an endpoint ID (taking
ownership of a reference) must call `channel_inc_ref()`. This applies not
just to IPC message cap transfers, but also to internal bookkeeping
structures like `BootRegistration.overrides[]`. The `parse_ns_overrides()`
function was added after the Bug 0002 fix and didn't follow the established
pattern.

**Testing gap:** The original Bug 0002 fix added inc_ref in `merge_overrides`
(parent-to-child inheritance) and `ConnectService` handler (override delivery),
but missed the initial parsing path where overrides are first stored from the
spawn message. This highlights the need for regression tests that exercise the
full lifecycle: spawn with override, exit, spawn again.
