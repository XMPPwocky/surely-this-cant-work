# Feature

Design, scope, implement, and document a new feature for rvOS. Produce a
design doc at `docs/tasks/open/NNNN-FEATURE-slug.md` that serves as both the
implementation plan and permanent reference documentation. When complete,
move it to `docs/tasks/closed/`.

The argument to this skill is a description of the feature (what it should
do, why it's needed, any constraints). If no argument is provided, ask the
user to describe the feature.

## Phase 1: Intake

1. **Assign a task number.** Look at existing files in `docs/tasks/open/`
   and `docs/tasks/closed/` to find the highest NNNN. Increment by 1.
   If none exist, start at 0001.

2. **Choose a slug.** A short kebab-case name (e.g., `virtio-net`,
   `process-groups`, `block-device-fs`). The filename format is
   `NNNN-FEATURE-slug.md`.

3. **Record the current commit hash.** Run `git rev-parse --short HEAD` and
   include it in the design doc. This pins the exact codebase version the
   feature was designed against.

4. **Create `docs/tasks/open/NNNN-FEATURE-slug.md`** with the template below. Fill in
   what you know; mark unknowns with `TBD` — Phase 2 will resolve them.

```markdown
# NNNN: Title

**Date:** YYYY-MM-DD
**Status:** Design
**Type:** Feature
**Subsystem:** (e.g., kernel/ipc, kernel/mm, user/fs, lib/rvos, std-port)
**Commit:** (short hash from `git rev-parse --short HEAD` at time of creation)

## Motivation

Why this feature is needed. What problem does it solve? What does it
unblock? Reference arch review findings, complaints, or milestone goals
if applicable.

## Design

### Overview

Brief description of the approach (1-2 paragraphs).

### Interface Changes

New or changed syscalls, IPC protocols, shell commands, or library APIs.
Include wire format, register layouts, or function signatures.

### Internal Changes

What kernel/user code changes. Which files are touched, which data
structures are added or modified.

### Resource Limits

Any new fixed-size tables, constants, or limits introduced. What happens
when they're exhausted? (Must not be silent failure.)

## Blast Radius

(Filled in during Phase 2)

## Acceptance Criteria

(Filled in during Phase 2)

## Deferred

(Filled in during Phase 2 — things explicitly out of scope)

## Implementation Notes

(Updated during Phase 3)

## Verification

(Updated during Phase 4)
```

5. **Update the doc as you go.** Every phase should update the relevant
   section of the design doc in-place.

## Phase 2: Design & Blast Radius

This is the most important phase. The project's recurring anti-patterns
("update X forget Y", stale constants, silent capacity limits) all stem
from insufficient upfront analysis. Take the time to do this right.

### 2a: Understand the Existing Code

Read the code you're about to change. Don't design in a vacuum.

- Read the files in the affected subsystem
- Check MEMORY.md for prior work, lessons learned, and known issues
  in this area
- Check `docs/arch-review-*.md` for relevant findings
- Check `docs/complaints/` for related open issues
- Read any existing protocol docs in `docs/protocols/`

### 2b: Blast Radius Analysis

**This prevents the "update X forget Y" bug class.** For every change in
your design:

1. **Grep for all affected constants.** If you're changing a limit,
   message format, or syscall number, find every place it's defined or
   referenced. List them in the Blast Radius section.

2. **Grep for all callers of functions you're changing.** If you're
   modifying a function signature, find every call site. Count them.

3. **Identify cross-boundary changes.** Does this touch:
   - Kernel ABI? (syscall numbers, register conventions) → must update
     `docs/kernel-abi.md` AND `lib/rvos/src/raw.rs`
   - Wire protocols? → must update `lib/rvos-proto/` AND protocol docs
     AND std sysroot PAL (requires `make build-std-lib`)
   - The std sysroot? → requires `make build-std-lib` + `cargo +rvos clean`
     on all user crates

4. **Check capacity limits.** Does your feature add processes, channels,
   handles, or memory allocations? Will existing limits accommodate it?
   Will existing limits need bumping?

5. **Write it down** in the Blast Radius section as a table:

```markdown
## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| New SYS_FOO syscall | trap.rs, raw.rs, kernel-abi.md | Low (additive) |
| Modify Channel struct | ipc/mod.rs, 12 callers of channel_send | Medium (signature change) |
| New protocol message | rvos-proto/foo.rs, std PAL | Medium (requires std rebuild) |
```

### 2c: Acceptance Criteria

Write concrete, verifiable acceptance criteria. Follow the milestone-1.md
pattern:

- Each criterion has a checkbox `- [ ]`
- Mix of: automated tests, manual testing, code inspection (grep), and
  performance checks
- Include a "no regressions" criterion: existing tests still pass, bench
  numbers don't degrade

### 2d: Explicit Deferrals

List things that are related but NOT in scope, with a brief rationale.
This prevents scope creep and documents conscious decisions.

```markdown
## Deferred

| Item | Rationale |
|------|-----------|
| Access control for new resource | Needs permissions model design first |
| Persistent storage | Out of scope; current feature uses in-memory only |
```

### 2e: Get Approval

Before implementing, present the design doc to the user. Use
AskUserQuestion if there are open design decisions (e.g., "Should this be
a kernel task or a user-space daemon?"). The design doc should be complete
enough that the user can evaluate scope, blast radius, and acceptance
criteria.

## Phase 3: Implement

1. **Follow the design.** If you discover something unexpected during
   implementation, update the design doc — don't silently deviate.

2. **Check blast radius items as you go.** Every entry in the Blast Radius
   table should be addressed. Don't leave any behind.

3. **Update constants everywhere.** If you add a syscall number, protocol
   tag, or limit, grep for all definition sites and update them all in the
   same commit.

4. **Update docs synchronously.** Protocol docs, kernel-abi.md, and other
   reference docs should be updated in the same commit as the code, not
   deferred.

5. **Update the "Implementation Notes" section** with anything noteworthy:
   surprises, deviations from the design, tricky parts, things the next
   person should know.

## Phase 4: Verify

1. **Walk the acceptance criteria.** Check every box. If a criterion
   can't be met, explain why in the Verification section and discuss
   with the user.

2. **No-regression check:**
   - `make build` succeeds
   - System boots and reaches shell
   - `make bench` shows no significant regression (>20% on any benchmark)
   - Existing tests still pass

3. **Run the feature.** Exercise the new functionality end-to-end.
   Document what you tested in the Verification section.

4. **Check for stale constants.** Grep for any old values that should
   have been updated (the "stale chunk sizes" anti-pattern).

5. **Update the design doc** — mark all acceptance criteria boxes,
   fill in the Verification section with results.

## Phase 5: Commit & Close

1. **Commit the implementation.** Follow the project's commit style:
   ```
   Add [brief description of feature]

   [What was added and why]
   [Key design decisions]
   [What changed in existing code]

   Feature: NNNN
   Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
   ```

2. **Move the design doc** from open to closed:
   ```
   git mv docs/tasks/open/NNNN-FEATURE-slug.md docs/tasks/closed/NNNN-FEATURE-slug.md
   ```

3. **Update the design doc status** to `**Status:** Complete (YYYY-MM-DD)`.

4. **Commit the doc move** (can be part of the same commit or a separate one).

5. **Update MEMORY.md** if the feature is significant:
   - Add to "Features" section
   - Add any key learnings
   - Update resource limits if changed

6. **Update CLAUDE.md** if the feature introduces new conventions that
   agents should follow.

7. **Check for documentation drift.** Does README.md need updating?
   Does `docs/architecture.md` need a new section? Are all protocol
   docs current?

## When NOT to Use This Skill

- **Trivial features** (bumping a constant, adding a simple shell command):
  just do it directly, no design doc needed.
- **Bug fixes**: use `/bug` instead.
- **Architecture reviews**: use `/arch-review` instead.
- **Milestone planning** (scoping multiple features from an arch review):
  that's a manual process — read the arch review, write the milestone doc
  by hand following the `docs/milestones/milestone-1.md` pattern.

## Design Doc Philosophy

The design doc serves two purposes:

1. **Before implementation**: It's a plan that catches "update X forget Y"
   risks, makes scope explicit, and gets user buy-in on the approach.

2. **After implementation**: It's permanent reference documentation — like
   `docs/shared-memory.md` or `docs/rpc-framework.md`. Future agents and
   sessions can read it to understand why the feature works the way it does.

Keep it honest and useful. If the design changed during implementation,
update the doc to reflect reality, not the original plan.
