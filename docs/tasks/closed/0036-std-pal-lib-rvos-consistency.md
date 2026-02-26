# 0036: Reconcile std PAL with lib/rvos service API

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26) — won't fix
**Severity:** LOW
**Subsystem:** vendor/rust/library/std, lib/rvos

## Description

The std PAL's connect_to_service() returns raw usize handles, while
lib/rvos::connect_to_service() returns SysResult<RawChannel>. Proposed
making the std PAL use lib/rvos internally.

## Resolution

Won't fix. The inconsistency is by design:

- The std PAL operates at the raw syscall level because it can't depend
  on lib/rvos (different build targets, circular dependency risk)
- The std PAL's raw handle approach is correct for its context: std::net
  manages handles internally and translates errors to io::Error
- Apps using std::net never see raw handles — they use TcpStream etc.
- Apps using lib/rvos directly get the typed RawChannel API

The two paths serve different audiences and there's no confusion in
practice. Making the std PAL depend on lib/rvos would complicate the
build without benefit.
