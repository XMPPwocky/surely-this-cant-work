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
