# 0004: Namespace Override Propagation

**Date:** 2026-02-10
**Status:** Done
**Subsystem:** kernel/services/init

## Motivation

Namespace overrides let a parent remap service names for a child process
(e.g., fbcon overrides `stdin`/`stdout` so its shell talks to the
framebuffer console instead of the serial console). But when that child
spawns a grandchild, the overrides are **not inherited** — the grandchild
falls back to the global service registry (serial console).

Concrete example: fbcon spawns `/bin/shell` with `stdin`→fbcon,
`stdout`→fbcon. The shell runs `run /bin/hello`. `hello` gets its
stdout from the serial console, not the framebuffer, because the
shell's Spawn request carries no overrides.

This makes namespace overrides useless for anything but direct children,
defeating their purpose as a lightweight namespace mechanism.

## Design

### Overview

Two changes:

1. **Propagation**: When init handles a `Spawn` request, it merges the
   parent's overrides as defaults underneath any explicit overrides from
   the Spawn message. Explicit overrides win on name conflict.

2. **Removal**: An explicit `action` byte in the wire format (0=redirect,
   1=remove) and a `removed: bool` field on `NsOverride` let a parent
   explicitly clear an inherited override so the child falls through to
   the global service registry. No sentinel values.

Additionally, `MAX_NS_OVERRIDES` is increased from 4 to 16 to accommodate
deeper override chains.

### Interface Changes

**Wire format change** (breaking — all 2 in-tree callers updated): Each
entry in the packed `ns_overrides` blob gains an `action` byte:

Old format:
```
[count: u8] then count * [name_len: u8, name_bytes..., cap_index: u8]
```

New format:
```
[count: u8] then count * [name_len: u8, name_bytes..., action: u8, cap_index: u8]
```

Where `action = 0` means redirect (use `caps[cap_index]`), and
`action = 1` means remove (the `cap_index` byte is still present for
fixed-size parsing but ignored; use 0 as placeholder).

**User-space callers to update:**
- `user/shell/src/shell.rs` — `cmd_run` redirect override blob
- `user/fbcon/src/main.rs` — stdin/stdout override blob for shell spawn

### Internal Changes

In `kernel/src/services/init.rs`:

1. **Increase `MAX_NS_OVERRIDES`** from 4 to 16.

2. **Add `removed: bool` to `NsOverride`**.

3. **`parse_ns_overrides` change**: Read the new `action` byte. If
   `action == 1`, set `removed = true` on the entry.

4. **Add `get_parent_overrides(boot_ep_b) -> [Option<NsOverride>; MAX_NS_OVERRIDES]`**
   — copies the parent's overrides from INIT_CONFIG.

5. **Add `merge_overrides(parent, explicit) -> [Option<NsOverride>; MAX_NS_OVERRIDES]`**
   — starts with all `explicit` entries, then fills remaining slots with
   parent entries whose names aren't already present in the explicit set
   (a removal entry blocks the parent's override with the same name).

6. **In `handle_spawn_request`**: after `parse_ns_overrides`, call
   `get_parent_overrides` + `merge_overrides` to produce the final set.

7. **`find_ns_override` change**: skip entries where `removed == true`
   (return `None`, so lookup falls through to global).

### Resource Limits

`MAX_NS_OVERRIDES` increases from 4 to 16. Each `NsOverride` is ~33 bytes
(+ Option overhead). Per `BootRegistration`: 16 entries ≈ 640 bytes.
With `MAX_BOOT_REGS = 16`, worst-case total ≈ 10 KB. Acceptable.

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| Increase MAX_NS_OVERRIDES 4→16 | init.rs | Low (array sizing) |
| Add `removed` field to NsOverride | init.rs | Low (struct-internal) |
| Wire format: add action byte | init.rs, shell.rs, fbcon/main.rs | Medium (3 files, but mechanical) |
| Add get_parent_overrides fn | init.rs | Low (new function) |
| Add merge_overrides fn | init.rs | Low (new function) |
| Modify handle_spawn_request | init.rs (1 call site) | Low (additive) |
| find_ns_override: skip removals | init.rs | Low |

No kernel ABI changes. No syscall changes. No std sysroot changes.

## Acceptance Criteria

- [ ] When fbcon's shell runs `run /bin/hello`, hello's stdout goes to fbcon (not serial)
- [ ] Explicit overrides in Spawn still take priority over inherited ones
- [ ] A removal entry (`action=1`) blocks inheritance of that name
- [ ] `make build` succeeds
- [ ] System boots and reaches shell (`make run`)
- [ ] Existing shell `run /bin/foo > output.txt` redirect still works
- [ ] No regression: `make bench` numbers within 20%

## Deferred

| Item | Rationale |
|------|-----------|
| User-space builder API for override blobs | Ergonomic improvement; not needed for this feature |
| Override introspection / listing API | No use case yet |

## Implementation Notes

- `MAX_NS_OVERRIDES` changed from 4 to 16 in `init.rs:19`
- `NsOverride` struct: added `removed: bool` field
- `parse_ns_overrides`: reads `action` byte between name and `cap_index`; action=1 creates a removal entry
- `get_parent_overrides(boot_ep_b)`: copies parent's overrides array from INIT_CONFIG
- `merge_overrides(parent, explicit)`: explicit entries first, then fills remaining slots with parent entries whose names don't collide (removal entries block parent names)
- `handle_spawn_request`: calls `get_parent_overrides` + `merge_overrides` after `parse_ns_overrides`
- `find_ns_override`: returns `None` for entries with `removed == true`
- `user/shell/src/shell.rs`: redirect blob updated from 9 to 10 bytes (action=0 inserted)
- `user/fbcon/src/main.rs`: override blob updated from 16 to 18 bytes (action=0 inserted per entry)

## Verification

- `make build`: passes (no errors, only pre-existing warnings)
- `make bench`: passes, numbers within expected range
- System boots and reaches shell via serial console
