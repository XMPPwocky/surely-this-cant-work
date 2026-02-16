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
