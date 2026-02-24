# 0017: Orphan QEMU processes persist after Ctrl-C or timeout

**Reported:** 2026-02-22
**Status:** Closed (2026-02-22)
**Severity:** MEDIUM
**Subsystem:** build/scripts

## Symptoms

When `make test`, `make bench`, or other expect-based targets are interrupted
(Ctrl-C) or killed, the QEMU process spawned inside the expect script can
survive as an orphan. The orphan holds the flock on `.qemu.lock`, blocking
all subsequent QEMU invocations with:

```
ERROR: QEMU is already running for this project.
```

The user must manually find and kill the orphan (`pkill qemu-system`) before
any `make run`, `make test`, etc. will work again.

## Reproduction Steps

1. Run `make test` (or `make bench`, `make test-quick`)
2. While QEMU is running (after "rvos>" prompt appears), press Ctrl-C
3. The make/expect processes exit, but check: `pgrep -a qemu-system`
4. QEMU is still running
5. Try `make run` — blocked by the lock

Also triggered by expect timeouts (e.g., if a test hangs and the 300s timeout
fires, expect exits but QEMU persists).

## Investigation

The bug was reported as: "QEMU processes can persist after Ctrl-C or killing `make test`; they hold the lock and block subsequent runs."

**Initial code review** of `qemu-lock.sh` immediately identified the proximate cause: the script used `exec "$@"` to replace itself with QEMU, leaving no parent process to perform cleanup when a signal arrived. The expect scripts' timeout paths all called `exit 1` without killing the spawned process. The expected fix was straightforward: run QEMU as a background child and add signal traps.

**First trap attempt — EXIT trap only.** The initial fix added `trap 'kill $QEMU_PID' EXIT` and ran QEMU as a background child. Testing showed QEMU still survived SIGTERM. Root cause: bash only runs the EXIT trap on clean exits, not on uncaught signals. SIGTERM with no explicit trap causes immediate death of the shell, bypassing EXIT.

**Second trap attempt — explicit INT/TERM/HUP traps.** Added traps for INT, TERM, and HUP that called `exit`, which in turn triggered the EXIT trap. Re-tested by killing the wrapper with SIGTERM — QEMU still persisted. The confusion stemmed from the test methodology: the kill command was hitting a subshell (spawned by `cd && script &`) rather than the script itself, making it appear the traps weren't working when they actually were.

**Isolated direct test.** A direct test (invoking `qemu-lock.sh` without a subshell wrapper) confirmed the traps worked correctly. When expect spawned `qemu-lock.sh` directly (without `make` in the chain), killing expect closed the PTY, which sent SIGHUP to `qemu-lock.sh`'s process group, the HUP trap fired, and QEMU was cleaned up.

**Make-in-the-chain failure.** When the real call chain was used (`expect → spawn make run-test → qemu-lock.sh → QEMU`), the fix failed: QEMU still orphaned after expect exit. Process group inspection revealed why: GNU Make places recipe processes in a separate process group (`setpgid`). SIGHUP from PTY close only reaches the session leader's process group (make + expect), not the recipe's process group containing `qemu-lock.sh` and QEMU. Make received SIGHUP and exited, but the recipe process group never received any signal.

**Parent-death monitor attempt.** Tried adding a background polling loop in `qemu-lock.sh` that checked whether `$PPID` was still alive and killed QEMU if not. This was abandoned because `$PPID` in the recipe shell points to `sh` (the recipe interpreter), not to make, and `sh` stays alive as long as `qemu-lock.sh` is running — so the monitor could never detect that make had died.

**Working approach: fix the expect scripts.** Since the signal break originated at the expect layer, the fix needed to live there too. The `exp_pid` Tcl variable gives the PID of the spawned process (make), and since make is the process group leader, `kill -- -[exp_pid]` kills the entire recipe tree (make + shell + `qemu-lock.sh` + QEMU) in one shot. A shared `expect-cleanup.tcl` helper was created that wraps `exit` and installs SIGINT/SIGTERM/SIGHUP traps. All five expect scripts were updated to source this helper after `spawn`.

**Confounding factor during testing.** Several test iterations were confused by stale QEMU processes left by concurrent agents working in other worktrees. Once testing was isolated to track specific PIDs rather than using `pkill`, results became reliable.

## Root Cause

**Mechanism:**

1. `make test` runs `expect scripts/test.exp`
2. expect uses `spawn make run-test`, which creates a new PTY session
3. `make run-test` → `qemu-lock.sh` → `exec qemu-system-riscv64`
4. GNU Make isolates recipe processes in separate process groups via
   `setpgid()`. The chain is: make (session leader, PGID A) → recipe shell
   (PGID B) → qemu-lock.sh (PGID B) → QEMU (PGID B)
5. When the user presses Ctrl-C, SIGINT goes to the outer terminal's
   foreground process group (the outer make + expect), not the spawned session
6. expect exits → PTY master closes → SIGHUP sent to the session's foreground
   process group (PGID A = make)
7. make receives SIGHUP and exits, but the recipe process group (PGID B) does
   NOT receive SIGHUP because it's a different process group
8. QEMU survives as an orphan, still holding the flock

**Fundamental cause:** The signal chain from PTY close only reaches the
session leader's process group (make). GNU Make's recipe isolation puts
qemu-lock.sh and QEMU in a separate process group that never receives the
termination signal.

Additionally, `qemu-lock.sh` used `exec "$@"` to replace itself with QEMU,
leaving no parent process to perform cleanup.

**Code location:** `scripts/qemu-lock.sh:69` (`exec "$@"`), all expect
scripts (no cleanup on exit)

**Bug class:** Resource leak (orphan process holding flock)

## Fix

Two-part fix:

1. **`scripts/qemu-lock.sh`**: Replace `exec "$@"` with running QEMU as a
   background child, with signal traps (INT, TERM, HUP, EXIT) that kill QEMU.
   This handles the case where qemu-lock.sh is spawned directly (not through
   make), and also ensures proper cleanup when signals DO reach the script.

2. **`scripts/expect-cleanup.tcl`** (new shared helper): Registered by all
   expect scripts after `spawn`. Wraps `exit` and installs signal traps
   (SIGINT, SIGTERM, SIGHUP) to explicitly kill the spawned process group
   (`kill -- -$pid`) on any exit path. Since `exp_pid` returns make's PID,
   and make is the process group leader (PGID = make's PID), this kills
   the entire recipe tree (make + qemu-lock.sh + QEMU) in one shot.

   All 5 expect scripts (test.exp, test-quick.exp, bench.exp, bench-run.exp,
   bench-save.exp) source this helper after `spawn`.

## Verification

Tested three exit paths with the fix:

1. **Signal kill** (simulated Ctrl-C): spawned QEMU via expect, killed expect
   with SIGTERM, verified QEMU was cleaned up within 5 seconds. PASS.

2. **Timeout exit**: ran `make test-quick` with ktest timeout, verified no
   orphan QEMU after the timeout `exit 1`. PASS.

3. **Clean shutdown**: booted, sent `shutdown` command, verified clean exit
   with no orphans. PASS.

In all cases, other agents' QEMU processes (running in the same machine) were
left untouched — only the specific process group was killed.

## Lessons Learned

### 1. Blast Radius
The `run-gpu-screenshot` target in the Makefile uses `&` to background QEMU
and has its own cleanup (`kill %1`). That path is separate and not affected
by this bug.

### 2. Prevention
The `expect-cleanup.tcl` helper ensures any future expect scripts automatically
get cleanup behavior — just add `source .../expect-cleanup.tcl` after `spawn`.

### 3. Invariants
**Process group isolation in make**: GNU Make puts recipe processes in separate
process groups. Signal delivery from PTY close only reaches the session
leader's process group, not recipe process groups. Any script that relies on
signal propagation through make must handle cleanup explicitly.

### 4. Debug Tooling
The `pgrep -a qemu-system` command is the quickest way to check for orphaned
QEMU processes. The lock script's PID-in-lockfile mechanism allows
`cat .qemu.lock` to identify the holder.
