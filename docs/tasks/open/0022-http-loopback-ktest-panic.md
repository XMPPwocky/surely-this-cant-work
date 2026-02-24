# 0022: Kernel panic in channel_inc_ref during HTTP loopback ktest

**Reported:** 2026-02-24
**Status:** Open
**Severity:** HIGH
**Subsystem:** ipc, init, net-stack

## Symptoms

Running `make test` (full test suite) with the new `test_http_loopback` ktest
causes a kernel panic:

```
--- HTTP Loopback ---
[init] Loaded http-server from fs (356376 bytes)
  Spawned user ELF [15] "http-server" (PID 15, boot_ep=72)

!!! KERNEL PANIC !!!
panicked at kernel/src/ipc/mod.rs:596:5:
channel_inc_ref: channel 40 is inactive
```

The panic occurs when spawning the http-server process as part of the ktest.
The test spawns http-server via the shell/init spawn protocol, but the channel
used for capability transfer is already inactive (deactivated/closed) by the
time `channel_inc_ref` is called.

## Reproduction Steps

1. Build: `. ~/.cargo/env && make build`
2. Run full tests: `make test`
3. Wait for "HTTP Loopback" section
4. Observe kernel panic at `channel_inc_ref: channel 40 is inactive`

The test is in `user/ktest/src/main.rs` function `test_http_loopback`.
The test works by spawning http-server on port 8080 via `service::spawn_by_name`,
then spawning http-client to fetch `http://127.0.0.1:8080/`.

## Investigation

(To be filled in during debugging)

## Root Cause

(To be filled in)

## Fix

(To be filled in)

## Verification

(To be filled in)

## Lessons Learned

(To be filled in)
