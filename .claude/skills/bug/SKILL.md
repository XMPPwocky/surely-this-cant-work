# Bug Tracker

Track, reproduce, root-cause, fix, and close bugs in rvOS. Produce a written
bug report at `docs/tasks/open/NNNN-slug.md`, then work through the bug lifecycle
to resolution.

The argument to this skill is a description of the bug (symptoms, how to trigger
it, any initial theories). If no argument is provided, ask the user to describe
the bug.

## Phase 1: Intake & Document

1. **Assign a bug number.** Look at existing files in `docs/tasks/open/` and
   `docs/tasks/closed/` to find the highest NNNN. Increment by 1. If none exist,
   start at 0001.

2. **Choose a slug.** A short kebab-case name for the bug (e.g.,
   `channel-leak-on-cap-transfer`, `idle-in-ready-queue`).

3. **Create `docs/tasks/open/NNNN-slug.md`** with this template:

```markdown
# NNNN: Title

**Reported:** YYYY-MM-DD
**Status:** Open
**Severity:** HIGH | MEDIUM | LOW
**Subsystem:** (e.g., ipc, scheduler, mm, init, fs, window-manager, std-port, shell)

## Symptoms

What the user observes. Be specific: "system hangs after running `ls` twice"
not "ls is broken."

## Reproduction Steps

Numbered steps to trigger the bug. Include make targets, shell commands,
expect scripts, or benchmark invocations. If the bug is intermittent, note
the success rate (e.g., "fails ~1 in 3 runs").

## Investigation

(Updated as you go during Phases 2-3. Document your debugging process:
what you tried, what you observed, what led to dead ends, what worked.)

## Root Cause

(Filled in during Phase 3)

## Fix

(Filled in during Phase 4)

## Verification

(Filled in during Phase 5)

## Lessons Learned

(Filled in during Phase 6)
```

4. **Update the doc as you go.** Every phase should update the relevant section
   of the bug doc in-place. Document your **investigation process**, not just
   your eventual conclusions — what you tried, what you observed, what led to
   dead ends, and what finally worked. This is valuable for future debugging:
   knowing that "enabling syscall tracing showed no unusual patterns, but adding
   a println in `schedule()` revealed the wrong PID" teaches more than just
   stating the root cause. The final closed doc is a complete post-mortem that
   captures both the answer and the path to finding it.

## Phase 2: Reproduce

Goal: Confirm the bug exists and have a reliable way to trigger it.

1. **Build the current codebase.** `. ~/.cargo/env && make build`

2. **Try to reproduce** using the reported symptoms. Use the appropriate test
   method:
   - **Serial shell commands**: Use `expect` scripts (see `docs/testing-serial.md`)
   - **Benchmark regressions**: `make bench`
   - **GUI/window bugs**: `make run-gpu-screenshot` or `make run-vnc`
   - **Boot failures**: `timeout 30 make run 2>&1 | tee /tmp/boot.log`

3. **If reproduction fails**, ask the user for more details using AskUserQuestion.
   Don't guess — the user may have context about specific conditions, timing,
   or configuration that triggers the bug.

4. **Once reproduced**, update the "Reproduction Steps" section of the bug doc
   with exact, copy-pasteable steps.

## Phase 3: Root Cause

Goal: Understand *why* the bug happens, not just *that* it happens.

### Debugging Toolkit

1. **Read the code.** Start with the subsystem identified in the symptoms.
   Follow the call chain. Check MEMORY.md for similar past bugs in the same
   subsystem — the same bug class often recurs.

2. **Check git history.** `git log --oneline -- path/to/suspect/file.rs` to
   see what changed recently. A regression is much easier to root-cause than
   a latent bug.

3. **Add targeted debug prints.** Add temporary `println!` at key decision
   points in the suspected code path. This is cheap, fast, and usually the
   quickest way to narrow down a bug. You can also use `SYS_TRACE` from
   user-space to write to the kernel trace ring buffer. Remove debug prints
   before committing.

4. **Enable syscall tracing.** Set `TRACE_SYSCALLS = true` in
   `kernel/src/arch/trap.rs`, rebuild, and run. Look for unexpected syscall
   patterns (e.g., a process making only 2 syscalls then blocking forever
   suggests a deadlock during init).

5. **Check memory.** Use the shell `mem` command to see per-tag heap usage.
   Run the reproducer multiple times and check if allocations grow (leak).

6. **Add scheduler tracing** (if scheduling-related). Add `[sched] PID -> PID`
   prints in the scheduler's `schedule()` function to see task switch patterns.
   Only reach for this if the bug looks like a scheduling issue, deadlock, or
   starvation — not for general debugging.

7. **Use kernel backtrace.** If there's a panic or page fault,
   `print_backtrace()` shows the call chain. Use
   `scripts/symbolize_addresses.py` to get function names.

8. **If stuck, ask the user.** Use AskUserQuestion to describe what you've
   found so far and ask for guidance. The user may have domain knowledge
   about invariants or subtle interactions.

### Root Cause Documentation

Update the "Root Cause" section with:
- **Mechanism**: Step-by-step explanation of how the bug manifests
- **Fundamental cause**: The underlying design flaw or mistake (not just
  "line 42 is wrong" but *why* it's wrong — e.g., "lock ordering violation",
  "check-then-act race", "silent drop on capacity limit")
- **Code location**: `file.rs:line` references
- **Bug class**: Categorize as one of: race condition, deadlock, resource leak,
  silent drop, memory corruption, stack overflow, off-by-one, protocol error,
  type confusion, or other

## Phase 4: Fix

1. **Implement the fix.** Prefer structural fixes over point fixes:
   - If this is a resource leak, consider adding an RAII wrapper
   - If this is a race, consider making the operation atomic
   - If this is a silent drop, add logging and use `Result` types
   - If this is a deadlock, use the snapshot-release-act pattern
   - Check MEMORY.md for the project's established patterns for each bug class

2. **Keep the fix minimal.** Don't refactor surrounding code or add unrelated
   improvements. The commit should be a clean, reviewable bug fix.

3. **Update the "Fix" section** of the bug doc with a description of the fix
   and the rationale.

## Phase 5: Verify

1. **Build**: `. ~/.cargo/env && make build` must succeed with no warnings
   relevant to your changes.

2. **Boot test**: The system must boot and reach the shell prompt.

3. **Reproduce the original bug**: Run the exact reproduction steps from
   Phase 2. The bug must not occur.

4. **Regression check**: Run existing tests to verify nothing broke:
   - `make bench` (if applicable — checks for perf regressions)
   - Interactive shell testing via expect scripts
   - Any test specific to the affected subsystem

5. **Stress test** (for race conditions or leaks): Run the reproducer 3-5x
   consecutively. Check `mem` output for stable heap usage.

6. **Update the "Verification" section** with what you tested and the results.

## Phase 6: Commit & Close

1. **Commit the code fix.** Follow the project's commit message format:
   ```
   Fix [brief description of bug]

   [Root cause explanation: what was wrong and why]
   [Fix explanation: what changed and why this is correct]
   [Verification: how the fix was tested]

   Bug: NNNN
   Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
   ```

2. **Move the bug doc** from open to closed:
   ```
   git mv docs/tasks/open/NNNN-slug.md docs/tasks/closed/NNNN-slug.md
   ```

3. **Update the bug doc status** to `**Status:** Closed (YYYY-MM-DD)` and
   ensure all sections are filled in.

4. **Commit the doc move** (can be part of the same commit or a separate one).

## Phase 7: Lessons Learned

This is the most important phase. Don't skip it.

Update the "Lessons Learned" section of the (now closed) bug doc with answers
to these questions:

### 1. Blast Radius
What other code might have the same bug? Grep for similar patterns. If you
find siblings, either fix them now (if trivial) or file them as new bugs.

### 2. Regression Test
Write a regression test that fails without the fix and passes with it. This
is not optional — bugs that aren't tested come back. The test should:
- Exercise the specific triggering condition from Phase 2
- Be a ktest if possible (permanent, runs in CI via `make test`)
- Be an expect script if the bug requires shell interaction or timing
- At minimum, be a `debug_assert!` at the violation site if a full test
  isn't feasible

### 3. Prevention
What test, assertion, or compile-time check would have caught this bug before
it shipped? Consider:
- A type-system change that makes the bug unrepresentable
- A `#[must_use]` annotation on a return value that was ignored
- A `debug_assert!` for the violated invariant
- A coding guideline for CLAUDE.md

### 4. Invariants
Is there a key invariant that was violated? Should it be documented in a
CLAUDE.md or as a code comment? If so, add it.

### 5. Memory & Documentation
Should anything be added to:
- **MEMORY.md**: Add a "Critical Bugs Found & Fixed" entry if the bug is
  non-trivial. Use the established format: `**symptom**: explanation. Fix: fix.`
- **CLAUDE.md**: Add a convention if this bug class could be prevented by
  a coding guideline
- **docs/**: Update any protocol docs, architecture docs, or API docs that
  were wrong or incomplete

### 6. Debug Tooling
Would a new debugging tool or diagnostic have made root-causing faster?
Consider:
- A new kernel shell command
- A new tracing mode
- A compile-time check
- A runtime assertion
- An expect-script test case

If a small tool (<50 lines) would help future debugging, implement it.

### 7. Escalation Notes
Following the agent model escalation policy in MEMORY.md: was this bug in
"Opus territory" (page tables, traps, user/kernel transitions, subtle
scheduling races)? If so, note it so future agents know to use Opus for
this subsystem.

## Philosophy

This skill embodies the project's debugging philosophy:

- **Quantify everything.** Don't say "it's slow" — measure it. Don't say
  "it leaks" — show the allocation counts before and after.
- **Every finding needs a location.** File path and line number, or it
  didn't happen.
- **Structural fixes over band-aids.** If the same bug class has appeared
  3+ times, the fix is architectural (RAII wrapper, type system enforcement,
  lock decomposition), not another point fix.
- **Silent drops are the worst bugs.** Always log when a limit is hit.
  Always check return values. Always use `Result` over sentinel values.
- **The bug doc is a post-mortem.** When it's closed, anyone reading it
  should understand: what happened, why, how it was fixed, and what we
  learned. This is institutional memory.
