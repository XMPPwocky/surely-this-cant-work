# 0039: Extract spawn_impl() helper in init server

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** kernel/services/init
**Source:** Arch review 3, carried through reviews 6-8

## Description

The init server's process spawning logic is repeated/interleaved across
multiple code paths (boot spawning, dynamic spawning via SpawnProcess
message, etc.). Extract a shared `spawn_impl()` helper that handles
ELF loading, process creation, namespace setup, and cap passing in one
place to reduce duplication and ensure consistent behavior.
