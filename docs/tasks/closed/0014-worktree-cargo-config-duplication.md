# 0014: Worktree builds fail due to duplicate cargo config

**Reported:** 2026-02-20
**Status:** Fixed
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

## Investigation

The bug was discovered incidentally while working on an unrelated feature in a worktree.
`make build` failed with an unexpected linker error — section overlap rather than a missing
file, which was unusual.

**Initial misdiagnosis.** The first theory (logged when filing the bug) was that the
user-space linker script path `../user.ld` resolved to a non-existent location inside the
worktree. This would explain `cannot find linker script` errors. However, the kernel error
(`section .text file range overlaps with .comment`) was different and pointed elsewhere.

**Noticing the duplicate flag.** Examining the linker command line in the error output
revealed `-T kernel/linker.ld` appearing **twice**. This was the actual cause of section
overlap: two identical linker scripts caused conflicting section placements. The `user/`
config duplication was also present but harmless (the linker tolerates a repeated `-T` for
the same file).

**Hunting the second source.** Since `.cargo/config.toml` only contained the flag once, the
question was where the second copy came from. Checked: no `kernel/.cargo/config.toml`, no
global `~/.cargo/config.toml`, no flag in `kernel/Cargo.toml`. The worktree itself had a
`.cargo/config.toml` — a copy of the main repo's.

**Identifying cargo's parent-directory walk.** The realization was that the worktree at
`.claude/worktrees/<name>/` is physically nested inside the main repo at `rvos/`. Cargo
walks from the working directory up to the filesystem root collecting all `.cargo/config.toml`
files it finds. From the worktree, the walk hits the worktree's copy at
`.claude/worktrees/<name>/.cargo/config.toml` and then, several levels up, the main repo's
copy at `rvos/.cargo/config.toml`. Cargo merges array values from all discovered configs,
so the rustflags array got doubled.

**Exploring fixes and dead ends.**

- *Option A (move worktrees outside the repo):* The `EnterWorktree` tool hardcodes
  `.claude/worktrees/` with no configuration knob. Ruled out.
- *Merging configs into one root file:* Would eliminate the separate `user/` config but
  still leave the worktree's root config exposed to the parent walk hitting the main repo's
  copy. Same duplication, just at a different level.
- *Option B (Makefile env vars):* `CARGO_TARGET_..._RUSTFLAGS` env vars are highest priority
  and override all config files. This would work, but the user rejected it — bare `cargo`
  invocations (without going through `make`) should continue to function.
- *`CARGO_ENCODED_RUSTFLAGS` test:* Attempted to verify the env-var approach during
  investigation. Initial test showed both `-T` flags still appearing even with the override;
  this turned out to be stale build artifacts from before the config change. A clean build
  (`cargo clean` first) confirmed env-var override works correctly.

**Finding the right fix.** The key insight was that `cargo:rustc-link-arg` emitted from
`kernel/build.rs` is a completely separate mechanism from the rustflags config system. It
fires exactly once per build, is not subject to hierarchical config merging, and can use
`CARGO_MANIFEST_DIR` for an absolute path to the linker script. Removing the linker flag
from `.cargo/config.toml` while keeping only `-C force-frame-pointers=yes` (which is
harmless when doubled) made the config files idempotent with respect to the parent walk.

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

Move the kernel linker script flag from `.cargo/config.toml` into
`kernel/build.rs` using `cargo:rustc-link-arg`. The `build.rs` approach
uses `CARGO_MANIFEST_DIR` for an absolute path, so it works regardless of
cargo's CWD or directory walk.

`.cargo/config.toml` retains only `-C force-frame-pointers=yes`, which is
harmless when duplicated by the parent-directory walk (the compiler accepts
the same flag twice).

The `build.rs` `cargo:rustc-link-arg` mechanism is separate from rustflags
and is not subject to cargo's hierarchical config merging — it emits link
args exactly once per build, regardless of how many config files are found.

### Changes

- **`kernel/build.rs`**: Added `cargo:rustc-link-arg=-T{manifest_dir}/linker.ld`
- **`.cargo/config.toml`**: Removed `-C link-arg=-T` and `-C link-arg=kernel/linker.ld`,
  kept only `-C force-frame-pointers=yes`

### Options considered but rejected

- **Option A (move worktrees outside repo):** The `EnterWorktree` tool
  hardcodes `.claude/worktrees/` — not configurable.
- **Option B (env vars in Makefile):** Breaks bare `cargo build`.
- **Option C (delete config from worktrees):** Leaves uncommitted changes
  to tracked files.

## Verification

1. Clean build with `CARGO_ENCODED_RUSTFLAGS="-Cforce-frame-pointers=yes"`
   (simulating post-merge state where config only has frame pointers):
   kernel links successfully with a single `-T` from build.rs.
2. `make clippy-kernel` — clean, no warnings.
3. `make build-user` — unaffected, still works.

## Lessons Learned

- `cargo:rustc-link-arg` from `build.rs` is immune to cargo's hierarchical
  config merging — it's a separate mechanism from rustflags. Use it for
  linker scripts when config duplication is a risk.
- Cargo's parent-directory `.cargo/config.toml` walk cannot be stopped.
  Keep config entries idempotent (safe to duplicate) or move them to
  `build.rs` where they're emitted exactly once.
