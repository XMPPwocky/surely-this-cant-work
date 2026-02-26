# 0040: Add socket port access control

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** user/net-stack
**Source:** Arch review 5, carried through reviews 6-8

## Description

Any user process can bind to any port (including well-known ports < 1024).
There's no access control or policy enforcement. Add a mechanism so that
privileged ports require some form of authorization (e.g., only processes
spawned with a specific capability can bind to ports < 1024).
