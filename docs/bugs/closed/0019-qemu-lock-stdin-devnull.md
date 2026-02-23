# 0019: qemu-lock.sh background job loses stdin — serial input broken

**Reported:** 2026-02-23
**Status:** Closed (2026-02-23)
**Severity:** HIGH
**Subsystem:** build/scripts
**Introduced by:** Bug 0017 fix

## Symptoms

All expect-based test scripts (`make test`, `make test-quick`, `make bench`)
hang after sending a command to the rvOS shell. The shell echoes typed
characters but never executes the command — `\r` appears lost.

Running QEMU directly (without `qemu-lock.sh`) works correctly.

## Reproduction Steps

1. `make test-quick`
2. Boot completes, shell prompt appears
3. expect sends `run /bin/ktest --quick\r`
4. Command echoes back but no test output appears
5. 60-second timeout fires

## Root Cause

Bug 0017's fix changed `qemu-lock.sh` from `exec "$@"` to `"$@" &` (run
QEMU as a background child) to enable signal-based cleanup. However, per
POSIX (and bash's implementation), when job control is disabled (the default
in non-interactive scripts), **asynchronous commands have their stdin
redirected from `/dev/null`**:

> "If job control is disabled, the standard input for an asynchronous list,
> before any explicit redirections are performed, shall be considered to be
> assigned to a file that has the same properties as /dev/null."
> — POSIX.1-2017, Shell Command Language, §2.9.3.1

So `"$@" &` causes QEMU to read stdin from `/dev/null` instead of from the
PTY. Consequences:

1. QEMU's `-serial mon:stdio` reads EOF immediately on stdin
2. QEMU never calls `tcsetattr()` on the PTY (it has `/dev/null`, not a tty)
3. The PTY retains default settings: ECHO on, ICANON on, ICRNL on
4. Characters sent by `expect` are echoed by the PTY driver (not by rvOS)
5. No characters ever reach the UART — the rvOS shell receives nothing
6. The "echo" visible in expect output is PTY-level echo, not shell echo

**Code location:** `scripts/qemu-lock.sh:76`

**Bug class:** Regression from 0017 fix (stdin loss in background job)

## Investigation

The bug presented as a timing or IPC issue, not a stdin issue. Significant
time was spent chasing false leads:

1. **Timing hypothesis**: Increased the sleep between prompt detection and
   command send from 1s to 3s and 5s. No effect — the same hang occurred
   regardless of delay.

2. **Character encoding hypothesis**: Tested `\r` vs `\n` vs slow
   character-by-character send. All produced the same result: characters
   echoed but command never executed.

3. **MCP comparison**: The same commands worked perfectly via the MCP server
   (which uses named pipes, not PTY/stdio). This narrowed the problem to
   the stdio transport path.

4. **Main branch test**: Verified the bug existed on main branch too (not
   a regression from ext2 changes). This ruled out any ext2-related cause.

5. **Kernel instrumentation**: Added debug prints to the serial console
   server to log delivered characters. Discovered that `\r` was never
   delivered to the shell in raw mode — but this was because the console
   was actually in **cooked mode** (QEMU never set the PTY to raw, so the
   PTY's own line discipline was processing characters).

6. **User hint**: The user pointed out the critical clue: "this doesn't
   happen if I run qemu-system directly, but does happen if I stick
   scripts/qemu-lock.sh in front". This immediately pointed to the
   `"$@" &` backgrounding as the cause.

The misleading PTY echo was the primary reason for the long investigation.
The output looked identical to normal shell echo, making it appear that
the shell was receiving input but failing to process it.

## Fix

Add explicit stdin preservation to the background command:

```bash
"$@" 0<&0 &
```

The `0<&0` redirect duplicates the script's stdin (fd 0) onto the child's
stdin before backgrounding. This overrides bash's implicit `/dev/null`
redirect for async commands, keeping QEMU connected to the PTY.

## Verification

After fix, `make test-quick` passes: 69 tests pass, 0 failures.

## Lessons Learned

### 1. POSIX async stdin redirect
Non-interactive shells redirect background jobs' stdin from `/dev/null`.
This is a well-known POSIX rule but easy to forget when converting
`exec "$@"` to `"$@" &`. The `0<&0` idiom explicitly preserves stdin.

### 2. Misleading echo
The PTY's default ECHO setting creates a convincing illusion that the
shell is receiving input. Characters echo back, but the echo comes from
the kernel's PTY driver, not from the guest OS. This made the bug appear
to be a timing or IPC issue rather than a missing-stdin issue.
