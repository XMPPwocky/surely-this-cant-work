# Architecture Review

Conduct a comprehensive architecture review of the rvOS codebase. Produce a written report at `docs/arch-review-N.md` (increment N from the highest existing review number).

## Review Process

1. **Determine scope.** Check `docs/arch-review-*.md` for prior reviews. This review should focus on changes since the last review — don't re-report known issues unless they've gotten worse. Use `git log` to find the commit range since the last review date.

2. **Spawn parallel reviewer agents.** Each reviewer explores the codebase independently and reports findings. Use these reviewer roles:

   - **Kernel Core**: mm, scheduler, traps, page tables, process lifecycle. Focus on lock ordering, interrupt safety, resource exhaustion paths, and panic-on-failure sites.
   - **IPC & Channels**: channel.rs, syscalls, message flow, handle lifecycle. Focus on ref counting correctness, blocked-process wake logic, queue backpressure, and capability transfer.
   - **Kernel Services**: console, sysinfo, math, gpu_server, kbd_server, mouse_server, init. Focus on per-client cleanup, control channel protocol correctness, and service restart/recovery.
   - **User Apps & Std Port**: user/*, vendor/rust/library/std PAL, lib/rvos/. Focus on sysroot/userlib/kernel ABI consistency, error handling at PAL boundary, and allocator correctness.
   - **Docs vs. Implementation**: Compare every doc in docs/ against actual code. Find stale constants, missing syscalls, wrong process lists, outdated protocol descriptions. Table format: Doc | Claim | Actual.
   - **Build System & Toolchain**: Makefile, .cargo/config.toml, build.rs, x.py integration. Focus on build reproducibility, fragile ordering dependencies, and cargo config leakage.
   - **Bug History & Patterns**: Analyze `git log --oneline` for bug-fix commits. Categorize by class (race, leak, silent drop, deadlock, overflow, off-by-one). Identify most-fixed subsystems and whether structural fixes have reduced recurrence.
   - **Coupling & Blast Radius**: Which modules have the most cross-file dependencies? What's the blast radius of changing a core struct (Process, Channel, Message)? Which changes would cascade across 5+ files? Identify hidden coupling through global statics.
   - **Failure & Exhaustion Analysis**: For every fixed-size resource (channels, handles, processes, mmap regions, queue depth, console clients, named services, files, children), answer: what happens when it fills up? Is the caller notified or does it silently fail/panic? Are there tests for exhaustion?

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

## 11. What's Good

Explicitly call out well-designed subsystems, clean abstractions, and good patterns
worth preserving or extending. Don't skip this — it informs what NOT to change.

## 12. Priority Action Items

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
