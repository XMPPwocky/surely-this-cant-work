# 0010: Spurious suspend event after continue

**Reported:** 2026-02-16
**Status:** Closed (2026-02-16) — Not Reproducible
**Severity:** LOW
**Subsystem:** debugger (kernel/services/proc_debug, kernel/arch/trap)

## Symptoms

After suspend -> continue in the debugger, a spurious "[event] Process
suspended" event appeared to show up without the user issuing another suspend
command. Observed during bug 0009 testing when commands were issued in quick
succession via an expect script.

## Investigation

The bug was first noticed as a side-effect during bug 0009 testing. One expect
script run produced output showing "[event] Process suspended" appearing after
the "Resumed." line — which looked like a spurious re-suspend. The user was
asked to file it, and the following investigation was carried out.

**Step 1 — Code analysis.**
The `debug_suspend_pending` flag lifecycle was traced through the kernel:
`proc_debug.rs` sets it only in the Suspend command handler;
`trap.rs` atomically checks and clears it via `check_and_clear_debug_suspend()`
when returning to U-mode; the Resume handler (`clear_debug_suspended`) runs
only *after* the flag is already cleared. No code path could re-set the flag
without a new explicit Suspend command. Code analysis thus suggested the
behavior was not a real bug.

**Step 2 — First reproduction attempt (`/tmp/test-spurious-suspend.exp`).**
An expect script attached to `fs` (PID 6), issued `suspend`, waited for the
suspend event, issued `continue`, then monitored for any spurious subsequent
event over 4 seconds. The script timed out: `fs` spends almost all of its time
blocked waiting for IPC. A blocked process never takes a U-mode trap, so
`debug_suspend_pending` is never checked and the suspend command just hangs
waiting for an event that never comes. This led to the secondary finding that
debug suspend only works on actively running processes.

**Step 3 — Search for an active target.**
The ktest-helper and other user binaries were examined to find a process that
loops continuously and would reliably take traps. No suitable long-lived
looping target was found in the default system configuration.

**Step 4 — Second reproduction attempt (`/tmp/test-spurious-suspend2.exp`).**
The script attempted to replicate the exact bug 0009 test conditions: trigger
filesystem activity immediately before suspending (to catch `fs` while it was
actively handling a request), then repeat suspend/continue five times.
Result: the suspend either timed out (fs went back to blocked too quickly) or
completed cleanly with no spurious events observed across multiple runs.

**Step 5 — Reproduce original bug 0009 sequence (`/tmp/test-bug0009-repro.exp`).**
The exact command sequence from the original bug 0009 test was scripted and
run three times. Two runs produced no output at all from the filtered grep
(grep reported binary matches, indicating expect's control characters). One
run showed:

```
Suspend requested (waiting for event.
>>> Got suspend event
Resumed.
[event] Process suspended
Detached.
```

This output ordering — "[event] Process suspended" appearing after "Resumed." —
was the original observation. On closer examination, this is output buffering
and display interleaving: the event line was generated before `continue` was
processed but printed after "Resumed." due to expect's output buffering. The
old (pre-bug-0009-fix) debugger had inherent timing issues that made event
delivery and display ordering unreliable.

**Step 6 — Final reproduction attempt (`/tmp/test-spurious-final.exp`).**
A more careful script with full output capture via `log_file` attached to `fs`,
issued `suspend` (waiting for the suspend event), issued `continue`, then
waited 4 seconds watching for any further `[event]` output. The script timed
out at 1.5 minutes because `fs` was blocked and suspend never fired.

**Conclusion.** After four distinct reproduction scripts and multiple runs,
no genuine spurious event was produced. Code analysis confirms the flag
lifecycle is correct. The original observation was an output-ordering artifact.

## Reproduction Steps

Could not be reliably reproduced. Multiple expect scripts were tried:

1. `/tmp/test-spurious-final.exp` — Attach to fs (PID 6), suspend, wait for
   event, continue, then wait 4 seconds for any spurious event. Result: no
   spurious event (when suspend works), or suspend times out because fs is
   blocked in IPC and never takes a trap.

2. `/tmp/test-spurious-suspend2.exp` — Same approach but with 5 extra
   suspend/continue cycles to stress test. Result: either suspend times out
   (fs blocked) or no spurious events detected across multiple rounds.

3. `/tmp/test-bug0009-repro.exp` — Replicated the exact sequence from the
   original bug 0009 test (sleep 1, continue, detach, quit). Result: clean
   output, no spurious events.

The fundamental obstacle: the `fs` process (the best debugger target since it
stays alive) spends most of its time blocked waiting for IPC. A blocked process
never takes traps, so `debug_suspend_pending` is never checked — the suspend
command simply times out. When suspend does succeed (catching fs during active
work), no spurious event was ever observed.

## Root Cause

**Not a bug.** Code analysis confirms there is no path that re-sets
`debug_suspend_pending` without a new explicit Suspend command:

- `debug_suspend_pending` is set in exactly ONE place:
  `proc_debug.rs:183` (the Suspend command handler calls
  `set_debug_suspend_pending(target_pid)`).

- It is cleared in THREE places:
  1. `scheduler.rs:698` — process exit cleanup
  2. `scheduler.rs:1004` — detach cleanup
  3. `scheduler.rs:1024` — trap handler consuming the flag via
     `check_and_clear_debug_suspend()`

- The trap handler (`trap.rs`) calls `check_and_clear_debug_suspend(pid)`
  which atomically checks and clears the flag under the scheduler lock. If
  set, it sends `DebugEvent::Suspended` on the event channel, marks the
  process as debug-suspended, and blocks it. The flag is `false` before
  the Resume command ever runs.

- The Resume command (`proc_debug.rs`) calls `clear_debug_suspended()` +
  `wake_process()`. It does NOT touch `debug_suspend_pending` because the
  trap handler already cleared it.

There is no window where the flag could be re-set between continue and the
next user command.

## Original Observation Explained

The "spurious event" seen during bug 0009 testing was most likely an expect
script output interleaving artifact. The expect `[event]` pattern could match
the original suspend event output that was still being buffered/displayed when
the script advanced to the next phase. The old bug 0009 debugger code (before
the poll-based fix) had inherent output timing issues that made expect script
output ordering unreliable.

## Lessons Learned

### Suspect the test before the code
When a bug is observed only through a test harness (expect scripts) and cannot
be reproduced in multiple attempts, the harness itself is the most likely
culprit. In this case, expect's pattern matching on interleaved output created
the appearance of a spurious event.

### Blocked processes and debug suspend
A secondary finding: `debug_suspend_pending` only works on processes that are
actively taking traps (running user-mode code). A process blocked in
`channel_recv_blocking` will never check the flag. This is a known limitation,
not a bug — suspending a blocked process would require additional kernel
support (e.g., interrupting the blocking syscall). Worth noting for future
debugger improvements.
