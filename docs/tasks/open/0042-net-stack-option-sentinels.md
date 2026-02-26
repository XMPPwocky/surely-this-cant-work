# 0042: Replace usize::MAX sentinels in net-stack with Option

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** user/net-stack
**Source:** Arch review 7, backlog item 20

## Description

Net-stack uses `usize::MAX` as a sentinel value for "no handle" / "no
connection" in several places. Replace these with `Option<usize>` for
type safety and to prevent bugs where a sentinel value is accidentally
used as a real handle.
