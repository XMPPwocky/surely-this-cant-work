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

## Additional Findings

**There is no way to stop Cargo's directory walk.** Cargo always walks
from CWD to the filesystem root looking for `.cargo/config.toml` files.
There is no config key, boundary marker, or `.git` detection that stops
the walk early. This is a known limitation:
https://users.rust-lang.org/t/how-to-ignore-cargo-config-file-in-parent-folder/55232

**Cargo's four rustflags sources are mutually exclusive** (checked in
order, first match wins):

1. `CARGO_ENCODED_RUSTFLAGS` env var
2. `RUSTFLAGS` env var
3. All matching `target.<triple>.rustflags` config entries **joined**
4. `build.rustflags` config value

If an env var is set, config files are completely ignored (not merged).
This means `CARGO_TARGET_RISCV64GC_UNKNOWN_NONE_ELF_RUSTFLAGS` in the
Makefile would sidestep the duplication entirely — but moving flags out
of `.cargo/config.toml` is a larger change to the build setup.

**The user-space duplication is harmless.** The doubled `-T../user.ld`
doesn't cause errors (the linker tolerates it). Only the kernel's
`-T kernel/linker.ld` duplication causes actual failures (section
overlap). `make build-user` works from worktrees; only `make build`
(which includes the kernel) fails.

## Fix

Potential approaches:

### Option A: Move worktrees outside the repo tree

Instead of `.claude/worktrees/<name>/`, create worktrees at a sibling
location like `../rvos-worktrees/<name>/`. This prevents cargo's
parent-directory search from finding the main repo's config.

Requires updating the `EnterWorktree` tool configuration.

### Option B: Move linker flags to Makefile env vars

Set `CARGO_TARGET_RISCV64GC_UNKNOWN_NONE_ELF_RUSTFLAGS` and
`CARGO_TARGET_RISCV64GC_UNKNOWN_RVOS_RUSTFLAGS` in the Makefile,
then delete both `.cargo/config.toml` files. Env vars completely
override config files (no merging). All builds already go through
`make`, so bare `cargo` invocations are not a supported workflow.

### Option C: Delete only the root `.cargo/config.toml` from worktrees

A post-worktree-creation hook could delete or empty the root-level
`.cargo/config.toml` in the worktree, leaving only the main repo's
copy to be found by the walk. Since the walk finds exactly one copy,
no duplication occurs. Downside: the worktree has uncommitted changes
to a tracked file.

## Verification

(To be filled when fixed)

## Lessons Learned

(To be filled when fixed)
