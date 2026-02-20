# 0014: Worktree builds fail due to duplicate cargo config

**Reported:** 2026-02-20
**Status:** Open
**Severity:** LOW
**Subsystem:** build system

## Symptoms

Running `make build` from a git worktree at `.claude/worktrees/<name>/`
fails with kernel linker errors:

```
rust-lld: error: unable to place section .text at file offset [0x1000, 0x27119]
rust-lld: error: section .text file range overlaps with .comment
```

The linker script `-T kernel/linker.ld` appears **twice** in the linker
command line, causing section layout conflicts.

User-space `cargo build` from inside the `user/` subdirectory also fails
with `cannot find linker script ../user.ld`, but this same failure occurs
in the main tree too (it's a pre-existing issue, not worktree-specific).

## Reproduction Steps

1. Create a worktree:
   ```
   git worktree add .claude/worktrees/test -b test-branch
   ```

2. Try to build the kernel from the worktree:
   ```
   cd .claude/worktrees/test
   make build
   ```

3. Observe kernel link failure with duplicate `-T kernel/linker.ld` flags.

4. User-space builds work if invoked correctly:
   ```
   # Works (from worktree root, using --manifest-path):
   make build-user

   # Fails (from inside user/ directory, without --manifest-path):
   cd user && cargo +rvos build --release --target riscv64gc-unknown-rvos -p nc
   ```

## Root Cause

Cargo searches for `.cargo/config.toml` by walking up the directory tree
from the current working directory. Worktrees at
`.claude/worktrees/<name>/` are physically nested inside the main repo at
`rvos/`. This means cargo finds **two** config files:

1. `.claude/worktrees/<name>/.cargo/config.toml` (worktree's copy)
2. `rvos/.cargo/config.toml` (main repo, found by parent-dir traversal)

Both contain the same `[target.riscv64gc-unknown-none-elf]` rustflags
section with `-T kernel/linker.ld`. Cargo **merges arrays** from
hierarchical configs, so the linker script flag appears twice.

For user-space, both configs specify `-T../user.ld`. The duplication is
harmless (the linker tolerates a repeated `-T` pointing to the same file),
but the relative path `../user.ld` only resolves correctly when cargo's
CWD is the worktree (or main repo) root, not when inside `user/`.

### Why `make build-user` works but `cd user && cargo build` doesn't

The Makefile invokes cargo from the repo root:
```
cargo +rvos build --release --manifest-path user/Cargo.toml --target ...
```

This sets the workspace root to `user/` but cargo's process CWD stays at
the repo root. The linker inherits this CWD, so `../user.ld` resolves
relative to the repo root... somehow (the exact resolution path is unclear
but the build succeeds). Running `cargo` directly from inside `user/`
changes the CWD, breaking the relative path.

## Fix

Two potential approaches:

### Option A: Move worktrees outside the repo tree

Instead of `.claude/worktrees/<name>/`, create worktrees at a sibling
location like `../rvos-worktrees/<name>/`. This prevents cargo's
parent-directory search from finding the main repo's config.

Requires updating the `EnterWorktree` tool configuration.

### Option B: Use absolute linker script paths

Change `.cargo/config.toml` and `user/.cargo/config.toml` to use
paths based on `CARGO_MANIFEST_DIR` or an absolute path. However,
cargo config.toml doesn't support environment variable expansion in
`rustflags`, so this may require a `build.rs` approach instead.

### Option C: Add `.cargo/config.toml` to worktree with adjusted paths

Use a post-worktree-creation hook to generate a `.cargo/config.toml`
that uses absolute paths to the worktree's own linker scripts.

## Verification

(To be filled when fixed)

## Lessons Learned

(To be filled when fixed)
