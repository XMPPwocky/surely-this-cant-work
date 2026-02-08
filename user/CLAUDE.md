# rvOS User-Space Programs

User-space programs run on top of the rvOS microkernel using the custom Rust std sysroot.

## Build
- `make build-hello` — build hello-std (and other user binaries)
- `make build-std-lib` — rebuild the std sysroot (after modifying vendor/rust/library/)
- After rebuilding std, run `cargo +rvos clean` in each user crate before rebuilding

## Conventions
- All user crates use `cargo +rvos` with the `riscv64gc-unknown-rvos` target
- No build.rs scripts (the rvos toolchain has no host std)
- IPC via capability channels using the `rvos` crate (lib/rvos/)
- Use `rvos::raw::*` for direct syscalls, `rvos::channel::*` for higher-level IPC

## Kernel Changes
Agents working on user-space programs should NOT hesitate to recommend or request
kernel changes when appropriate. Examples:
- A bug is discovered in a kernel service or syscall
- New kernel functionality would significantly simplify a user-space implementation
- A resource limit is too low (e.g., MAX_CHANNELS, MAX_HANDLES, MAX_CONSOLE_CLIENTS)
- A kernel API is awkward or error-prone for user-space consumers

When you identify such a case, flag it clearly and ask the user whether a kernel
change should be made rather than working around the issue in user-space alone.
