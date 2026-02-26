# 0036: Reconcile std PAL with lib/rvos service API

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** vendor/rust/library/std, lib/rvos
**Source:** Arch review 8, item 8

## Description

The std PAL's `connect_to_service()` returns raw `usize` handles, while
`lib/rvos::connect_to_service()` returns `SysResult<RawChannel>`. Apps
using std (e.g., via `std::net`) go through a different path than apps
using lib/rvos directly, creating inconsistent error handling and resource
management.

Should make the std PAL use lib/rvos internally, or at minimum ensure the
two paths have consistent semantics and RAII cleanup.
