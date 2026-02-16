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
Don't hesitate to recommend kernel changes when appropriate (bugs, missing
functionality, low resource limits, awkward APIs). Flag it and ask the user
rather than working around the issue in user-space alone.
