# 0023: Release builds have no runtime symbol names for backtraces

**Reported:** 2026-02-24
**Status:** Open
**Severity:** MEDIUM
**Subsystem:** build, panic/backtrace

## Symptoms

When a kernel panic or page fault occurs, `print_backtrace()` (in
`kernel/src/arch/trap.rs:191`) prints only raw addresses:

```
  Backtrace:
    #0: ra=0x8020d1ea fp=0x80648d10
    #1: ra=0x80209a2c fp=0x80648d30
    #2: ra=0x8020b73e fp=0x80648d60
```

To get function names, the developer must pipe this through
`scripts/symbolize_addresses.py`, which reads symbols from the ELF file
on disk. This adds friction to every debugging session — especially for
agents, which must perform a multi-step offline symbolization process
instead of reading the backtrace directly.

## Root Cause

The kernel is loaded as a flat binary (`kernel.bin`) produced by:

```
rust-objcopy --strip-all -O binary kernel kernel.bin
```

Flat binaries have no section headers or symbol tables — `--strip-all`
is irrelevant since `-O binary` inherently discards all metadata. The
ELF on disk (`target/.../release/kernel`, 2.96 MB) retains 201 function
symbols and 2355 total symbols, but none of this is available at runtime.

Additionally, the release profile in `Cargo.toml` does not set `debug`
or `debuginfo`, so no DWARF info is generated (though DWARF wouldn't
help at runtime without an embedded parser anyway).

**Code locations:**
- `Makefile:102` — objcopy to flat binary
- `kernel/src/arch/trap.rs:191` — `print_backtrace()` prints raw addresses
- `Cargo.toml:6-9` — release profile (no debug settings)
- `.cargo/config.toml:2` — `force-frame-pointers=yes` (frame pointers work)

**Bug class:** Missing feature / poor debuggability tradeoff

## Suggested Fix

Embed a compressed function symbol table into the kernel binary. Approach:

1. **Build script or post-link step**: Extract function symbols from the
   ELF (name + address), sort by address, compress (simple delta encoding
   + string table), write to a `.symtab` section or a separate binary blob
   linked into the kernel.

2. **At runtime**: `print_backtrace()` resolves each `ra` address against
   the embedded table using binary search, printing:
   ```
     #0: ra=0x8020d1ea  kernel::ipc::channel_inc_ref+0x1a
     #1: ra=0x80209a2c  kernel::services::init::handle_spawn+0x8c
   ```

3. **Size budget**: The 201 function symbols with demangled names would
   be ~15-20 KB uncompressed. With delta-encoded addresses and a shared
   string table, likely 8-12 KB — <0.5% of the 2.8 MB kernel binary.
   Well worth the tradeoff.

Alternative simpler approaches:
- **Minimal**: Just set `debug = "line-tables-only"` in `[profile.release]`
  and keep the ELF as the QEMU `-kernel` argument (QEMU can load ELF
  directly). This adds ~50-100 KB to the ELF but doesn't help at runtime
  unless a DWARF parser is embedded. However, it makes GDB debugging and
  offline symbolization richer.
- **Medium**: Generate a `kernel.sym` file alongside `kernel.bin` containing
  `addr name` pairs, and have a Makefile target or expect script that
  auto-symbolizes panic output. Doesn't fix runtime but reduces friction.

## Reproduction Steps

1. Build: `. ~/.cargo/env && make build`
2. Boot with MCP or make run
3. Trigger any kernel panic (e.g., the test_http_loopback panic from Bug 0022
   before it was fixed)
4. Observe backtrace with only raw hex addresses
5. Must manually pipe output through `scripts/symbolize_addresses.py` to
   get function names

## Investigation

(Not applicable — this is a known design limitation, not a runtime bug.)

## Fix

(To be implemented.)

## Verification

(Pending fix — verify that `print_backtrace()` output includes function
names after a kernel panic.)

## Lessons Learned

(To be filled after fix.)
