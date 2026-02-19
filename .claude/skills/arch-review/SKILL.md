# Architecture Review

Conduct a comprehensive architecture review of the rvOS codebase. Produce a written report at `docs/arch-review-N.md` (increment N from the highest existing review number).

## Review Process

1. **Determine scope.** Check `docs/arch-review-*.md` for prior reviews. This review should focus on changes since the last review — don't re-report known issues unless they've gotten worse. Use `git log` to find the commit range since the last review date.

2. **Spawn parallel reviewer agents.** Each reviewer explores the codebase independently and reports findings. Use these reviewer roles:

   - **Kernel Internals**: mm, scheduler, traps, page tables, process lifecycle, channels, syscalls, message flow, handle lifecycle. Focus on lock ordering, interrupt safety, ref counting correctness, blocked-process wake logic, queue backpressure, capability transfer, resource exhaustion paths, and panic-on-failure sites.
   - **Services & Applications**: All kernel services (console, sysinfo, math, gpu_server, kbd_server, mouse_server, init) + user apps (user/*) + std PAL (vendor/rust/library/std) + userlib (lib/rvos/). Focus on per-client cleanup, protocol correctness, service restart/recovery, ABI consistency across sysroot/userlib/kernel, error handling at PAL boundary, and allocator correctness.
   - **Cross-cutting Analysis**: (a) Bug patterns — analyze `git log --oneline` for bug-fix commits, categorize by class (race, leak, silent drop, deadlock, overflow, off-by-one), identify most-fixed subsystems and whether structural fixes reduced recurrence. (b) Coupling — which modules have the most cross-file dependencies, blast radius of changing core structs (Process, Channel, Message), hidden coupling through global statics. (c) Exhaustion — for every fixed-size resource (channels, handles, processes, mmap regions, queue depth, console clients, named services, files, children), what happens when it fills up? Caller notified or silent fail/panic?
   - **Code Quality**: Scan for unidiomatic Rust and patterns that historically produce bugs in this codebase. Specifically: (a) Sentinel values instead of `Result` — `usize::MAX`, `-1`, bare integer error codes, `.unwrap_or(0)`, `let _ =` on fallible operations. (b) Unnecessarily low-level abstractions — raw `channel_send`/`channel_recv` where `define_protocol!`-generated helpers exist, raw syscalls where lib/rvos wrappers exist, manual buffer packing where structured message types exist. (c) Manual ref counting instead of RAII (`OwnedEndpoint`/`OwnedShm`). (d) Panics in recoverable paths — `unwrap()`/`expect()`/`panic!()` where a `Result` return would let the caller handle it. (e) Unnecessarily wide `unsafe` blocks. (f) Magic numbers — inline numeric constants instead of named consts. (g) Weak type safety — bare `u32`/`usize` where a newtype would prevent mixing up ID spaces. (h) Missing `#[must_use]` on Result-returning functions. (i) Lock held across blocking operations — SpinLock held across `channel_close`, `wake_process`, or blocking sends (should snapshot-under-lock-then-release-then-act). (j) Missing rollback on partial failure — multi-step operations that don't clean up on intermediate failure. (k) Unchecked arithmetic on external input — user-space values, device values, wire-format values without `checked_add`/`checked_sub`. (l) Missing or misplaced memory fences in shared-memory communication.
   - **Test Coverage**: Identify critical invariants and code paths that lack tests. Specifically: (a) Regression tests — cross-reference `docs/bugs/closed/` and bug-fix commits against `user/ktest/` to find past bugs with no regression test. (b) Newly-written code — identify features added since the last review and check whether they have any test coverage at all. (c) Documented invariants — find invariants stated in comments, CLAUDE.md, or design docs that are enforced only by convention, not by tests (e.g., ref counting rules, lock ordering, sscratch updates, cleanup-on-exit sequences). (d) Exhaustion paths — which resource limits (channels, handles, processes, mmap regions, etc.) have tests that exercise the full→error path? (e) Error paths — which error returns are never exercised by any test? Focus on paths where silent failure would cause a hang or data loss. Table format: What | Why It Matters | Suggested Test.
   - **Docs & Build**: Compare every doc in docs/ against actual code — find stale constants, missing syscalls, wrong process lists, outdated protocol descriptions (table: Doc | Claim | Actual). Also: Makefile, .cargo/config.toml, build.rs, x.py integration — build reproducibility, fragile ordering dependencies, cargo config leakage.

3. **Synthesize findings into the report.** Combine, deduplicate, and organize reviewer outputs into the following structure.

## Report Structure

```markdown
# Architecture Review N — YYYY-MM-DD

Scope: [commits since last review, major features added]
Codebase: ~X lines of Rust + assembly (use `find kernel/src user/ lib/ -name '*.rs' | xargs wc -l`)

## 1. Correctness Bugs (Fix Now)

### HIGH: [description]
**Location**: `file.rs:line`
**Problem**: ...
**Fix**: ...

### MEDIUM: [description]
...

## 2. Structural Problems

Architecture-level issues: god objects, missing abstractions, coupling, lock granularity.
Each with: what it is, why it matters, and a concrete refactoring path.

## 3. Security & Isolation

Table: Severity | Location | Issue | Impact
Focus on: user-kernel boundary validation, integer overflow, unchecked pointers,
capability leaks, resource exhaustion DoS vectors.

## 4. Performance Cliffs

Table: Location | Current | Should Be | Penalty
Quantify impact where possible (e.g., "16x overhead from 64-byte chunks").

## 5. Resource Exhaustion Audit

Table: Resource | Limit | On Exhaustion | Caller Notified? | Suggested Fix
Every fixed-size table/pool in the kernel gets a row.

## 6. API Consistency & Footguns

- Functions that look similar but behave differently (blocking vs non-blocking)
- Missing RAII wrappers / cleanup-on-drop
- Silent error swallowing
- Inconsistent return conventions

## 7. Code Duplication

Table: Pattern | Instances | Lines | Fix
Only patterns worth deduplicating (3+ instances or 20+ lines).

## 8. Documentation Drift

Table: Doc | Claim | Actual Code
Every constant, limit, syscall number, process name, or protocol description
that doesn't match reality.

## 9. Bug Pattern Analysis

Table: Pattern | Count | Most Recent | Structural Prevention
Derived from git history. Track whether past structural fixes reduced recurrence.

## 10. Dependency & Coupling Map

- Which files change together most often? (git log --name-only analysis)
- What's the blast radius of modifying Process, Channel, Message structs?
- Hidden coupling through globals/statics?

## 11. Code Quality

### Sentinel values & error handling
Table: Location | Current Pattern | Suggested Fix
(every `usize::MAX`, `-1`, `let _ =`, `.unwrap_or(0)`, catch-all error mapping)

### Low-level abstraction usage
Table: Location | Raw API Used | Higher-level Alternative Available
(raw channel_send where protocol helpers exist, raw syscalls where lib wrappers exist)

### Other quality issues
Group by category (RAII, unsafe scope, magic numbers, type safety, #[must_use],
lock scope, missing rollback, unchecked arithmetic, memory ordering).
Each with: Location | Issue | Fix.

## 12. Test Coverage Gaps

### Missing regression tests
Table: Bug | Fix Commit | Has Regression Test? | Suggested Test
(cross-reference docs/bugs/closed/ and bug-fix commits against user/ktest/)

### Untested new code
Table: Feature | Files | Test Coverage | Suggested Test

### Untested invariants & error paths
Table: Invariant/Path | Where Stated | Suggested Test

## 13. What's Good

Explicitly call out well-designed subsystems, clean abstractions, and good patterns
worth preserving or extending. Don't skip this — it informs what NOT to change.

## 14. Priority Action Items

### Immediate (fix this week)
1. ...

### Soon (next sprint)
1. ...

### Backlog (when convenient)
1. ...

Each item: one-line title + parenthetical rationale.
If prior review items were completed, note them as DONE with strikethrough.
```

## Review Philosophy

- **Quantify everything.** Don't say "this is slow" — say "16x overhead." Don't say "many callers" — say "23 call sites in 8 files."
- **Every finding needs a location.** File path and line number, or it didn't happen.
- **Severity is about blast radius.** HIGH = data corruption, security hole, or deadlock. MEDIUM = performance cliff, resource leak, or silent failure. LOW = code smell, inconsistency, or missing docs.
- **Propose structural fixes, not band-aids.** If the same bug class has appeared 3+ times, the fix is architectural (RAII wrapper, type system enforcement, lock decomposition), not another point fix.
- **Track progress.** Reference prior review items and mark completion status.
- **Challenge assumptions.** What invariants does the code assume but never checks? What happens if a user process is malicious, not just buggy? What if two rare conditions happen simultaneously?
- **Think about what's missing.** No error handling on this path — is that intentional or forgotten? No test for this edge case — is it tested implicitly or not at all? This resource has no limit — what happens at scale?
