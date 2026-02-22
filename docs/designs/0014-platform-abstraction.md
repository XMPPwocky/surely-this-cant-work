# 0014: Platform Abstraction Layer

**Date:** 2026-02-22
**Status:** Complete (2026-02-22)
**Subsystem:** kernel/platform, kernel/drivers, kernel/mm, kernel/arch

## Motivation

Every physical address, device base, IRQ number, RAM size, and timer
frequency in the kernel is a hardcoded constant tuned to `qemu-system-riscv64
-machine virt`. This makes it impossible to boot on any other RISC-V
platform — physical dev boards (SiFive Unmatched, StarFive VisionFive 2,
Milk-V) or even a differently-configured QEMU instance.

The coupling is wide but shallow: the constants are scattered across ~10
files but the driver logic itself is mostly device-standard (NS16550 UART,
SiFive PLIC, VirtIO MMIO). The fix is to:

1. Parse the FDT (Flattened Device Tree) that firmware already provides
2. Collect all platform-specific values into a single `PlatformInfo` struct
3. Parameterize drivers and init code to read from `PlatformInfo` instead
   of constants

This unblocks future work: physical board support, multi-hart boot, PCI
VirtIO, alternative interrupt controllers.

## Design

### Overview

Add a minimal FDT parser (`kernel/src/platform/fdt.rs`) that reads the
device tree blob OpenSBI passes in register `a1`. Populate a global
`PlatformInfo` struct with RAM regions, device addresses, IRQ mappings,
and timer frequency. Then replace every hardcoded address/IRQ/frequency
constant across the kernel with reads from `PlatformInfo`.

QEMU virt continues to work identically — the FDT it generates contains
exactly the values we currently hardcode. The difference is we now *read*
them instead of *assuming* them.

### Phase A: Boot Handoff — Save DTB Pointer

**boot.S**: Save `a0` (hart ID) and `a1` (DTB pointer) into callee-saved
registers before zeroing BSS, then pass them to `kmain`:

```asm
_start:
    mv      s0, a0          # hart_id
    mv      s1, a1          # dtb_ptr
    la      sp, _stack_top
    # ... zero BSS (uses t0/t1, not s0/s1) ...
    mv      a0, s0
    mv      a1, s1
    call    kmain
```

**kmain** signature changes to `fn kmain(hart_id: usize, dtb_ptr: usize)`.

### Phase B: FDT Parser

A new module `kernel/src/platform/fdt.rs` (~300 lines). No-alloc, operates
on a `&[u8]` slice of the raw DTB in memory. Capabilities:

- Validate FDT header (magic `0xd00dfeed`, version, size)
- Walk structure block tokens (`BEGIN_NODE`, `END_NODE`, `PROP`, `NOP`, `END`)
- Find nodes by path (e.g., `/memory@80000000`)
- Find nodes by `compatible` property (e.g., `"riscv,plic0"`)
- Read property values: raw bytes, `u32`, `u64`, `reg` (address/size pairs),
  string, `interrupts` (IRQ numbers)

Key types:

```rust
pub struct Fdt<'a> {
    data: &'a [u8],
    struct_offset: usize,
    strings_offset: usize,
}

pub struct FdtNode<'a> { ... }   // Iterator-style node walker
pub struct FdtProp<'a> { ... }   // Property accessor
```

The parser is deliberately minimal: it walks the flat structure
sequentially (no tree indexing, no allocation). This is fine because we
only parse the FDT once at boot.

### Phase C: PlatformInfo Struct

A new module `kernel/src/platform/mod.rs`:

```rust
pub struct MemRegion {
    pub base: usize,
    pub size: usize,
}

pub struct DeviceInfo {
    pub base: usize,
    pub size: usize,
    pub irq: u32,
}

pub struct VirtioMmioSlot {
    pub base: usize,
    pub irq: u32,
}

pub struct PlatformInfo {
    // Memory
    pub ram: MemRegion,

    // Boot hart
    pub boot_hart_id: usize,

    // Timer
    pub timebase_frequency: u64,    // ticks per second

    // Interrupt controller
    pub plic_base: usize,
    pub plic_size: usize,
    pub plic_context: u32,          // S-mode context for boot hart

    // Serial console
    pub uart_base: usize,
    pub uart_irq: u32,

    // CLINT (mapped for mtime readability, though we use SBI for timer)
    pub clint_base: usize,
    pub clint_size: usize,

    // VirtIO MMIO devices (discovered from FDT)
    pub virtio_mmio: [VirtioMmioSlot; MAX_VIRTIO_SLOTS],
    pub virtio_mmio_count: usize,
}
```

**Storage**: A `static PLATFORM: SpinLock<PlatformInfo>` initialized with
compile-time QEMU virt defaults. Overwritten once from FDT during early
`kmain`, before interrupts are enabled and before any driver init. All
subsequent reads go through accessor functions:

```rust
pub fn platform() -> PlatformInfo { *PLATFORM.lock() }
// Or individual accessors:
pub fn ram_base() -> usize { PLATFORM.lock().ram.base }
pub fn uart_base() -> usize { PLATFORM.lock().uart_base }
pub fn timebase_frequency() -> u64 { PLATFORM.lock().timebase_frequency }
// etc.
```

`PlatformInfo` is `Copy` (all fields are primitive/array) so locking is
instantaneous — copy the struct out, drop the lock.

**Fallback**: If `dtb_ptr` is 0 or FDT parsing fails, keep the QEMU virt
defaults and print a warning. This ensures the kernel still boots on QEMU
even if something goes wrong with FDT handoff.

### Phase D: Populate from FDT

A function `platform::init_from_fdt(dtb_ptr: usize)` that:

1. Validates the FDT header at `dtb_ptr` (it's in the SBI region,
   already identity-mapped at boot)
2. Reads `/memory` node → `ram.base`, `ram.size`
3. Reads `/cpus/cpu@0/timebase-frequency` → `timebase_frequency`
4. Finds `compatible = "riscv,plic0"` → `plic_base`, `plic_size`,
   computes `plic_context` from boot hart ID
5. Finds `compatible = "ns16550a"` (or `"ns16550"`) → `uart_base`,
   `uart_irq` from `interrupts` property
6. Finds `compatible = "riscv,clint0"` → `clint_base`, `clint_size`
7. Finds all `compatible = "virtio,mmio"` nodes → fills `virtio_mmio[]`
   with base addresses and IRQ numbers
8. Stores result in the `PLATFORM` global

### Phase E: Parameterize Drivers

**Frame allocator (`mm/frame.rs`)**:
- Replace `const RAM_BASE/RAM_END` with `platform::ram_base()` and
  `platform::ram_end()` (where `ram_end = ram.base + ram.size`)
- The bitmap is currently `[u64; 512]` (sized for exactly 128 MiB). Change
  to `[u64; MAX_BITMAP_LEN]` where `MAX_BITMAP_LEN` supports up to 1 GiB
  (or whatever we choose as max RAM). The `init()` function computes the
  actual frame count from the platform RAM size; unused bitmap entries
  stay zero (marked free, but above `TOTAL_FRAMES` so never allocated).
- `TOTAL_FRAMES` becomes a runtime value stored in the `FrameAllocator`

**UART (`drivers/uart.rs`)**:
- `Uart` already takes `base` in its constructor — good
- Change `static UART` initialization: init with a placeholder, then
  `platform::uart_base()` is used to reinitialize at boot. Or: init with
  QEMU default (works for early boot prints), then the FDT value
  (should be identical on QEMU, different on other boards)
- Remove the `const UART_BASE` module-level constant

**TTY raw fallback (`drivers/tty.rs`)**:
- `raw_uart_putchar()` hardcodes `0x1000_0000`. Change to read
  `platform::uart_base()`

**PLIC (`drivers/plic.rs`)**:
- Replace `const PLIC_BASE` and the context-1 offset calculations with
  values from `platform::plic_base()` and `platform::plic_context()`
- `enable_irq`, `plic_claim`, `plic_complete` all compute addresses from
  the platform base + context
- Remove `const UART_IRQ` — IRQ numbers come from the device's FDT entry

**VirtIO MMIO (`drivers/virtio/mmio.rs`)**:
- Replace `const VIRTIO_MMIO_BASE/STRIDE/SLOTS` with
  `platform::virtio_mmio_slots()` which returns the FDT-discovered list
- `probe()` and `probe_all()` iterate the platform's slot list instead of
  computing `BASE + i * STRIDE`
- Each slot carries its own IRQ number (from FDT), so the `1 + slot`
  formula is replaced with `slot.irq`

**VirtIO device drivers (blk, net, gpu, input, tablet)**:
- Replace `let irq = 1 + slot as u32` and
  `let irq = 1 + ((base - 0x1000_1000) / 0x1000) as u32` with looking up
  the IRQ from the platform slot entry
- `mmio::probe()` / `mmio::probe_all()` already return base addresses;
  extend to also return the associated IRQ

**Kernel page table (`arch/paging.rs`)**:
- Replace hardcoded device regions with a loop over platform-provided
  device addresses: UART, PLIC, CLINT, and each VirtIO MMIO slot
- Replace `0x8800_0000` with `platform::ram_end()`

**User page tables (`task/process.rs`)**:
- Same device region mappings — two functions
  (`build_user_page_table_from_elf` and the kernel-task variant) have
  duplicated hardcoded addresses. Both switch to platform accessors
- `MMAP_VA_LIMIT` may need adjustment if RAM base changes, but for now
  `0x8000_0000` works for any board with RAM at or above that address

**Timer (`arch/trap.rs`)**:
- Replace `const TIMER_INTERVAL: u64 = 1_000_000` with a runtime value
  computed as `platform::timebase_frequency() / 10` (100ms tick)
- Store in a `static` initialized during `enable_timer()`

**Backtrace (`arch/trap.rs`)**:
- Replace `KERN_LO`/`KERN_HI` with linker symbols `_text_start` and
  `platform::ram_end()`

**Boot banner (`main.rs`)**:
- Replace `"QEMU virt machine, 128 MiB RAM"` with dynamically formatted
  string showing actual RAM size from platform info

### Interface Changes

**No syscall, IPC protocol, or user-space ABI changes.** This is entirely
internal to the kernel. User-space programs are unaffected.

The only externally-visible change is `kmain`'s signature (assembly-level
calling convention from `boot.S`), which is not a public interface.

### Internal Changes

New files:
- `kernel/src/platform/mod.rs` — `PlatformInfo` struct, global, accessors
- `kernel/src/platform/fdt.rs` — FDT parser

Modified files (see Blast Radius table for full list):
- `kernel/src/arch/boot.S` — save a0/a1
- `kernel/src/main.rs` — kmain signature, FDT init call, remove hardcoded banner
- `kernel/src/mm/frame.rs` — runtime RAM range
- `kernel/src/drivers/uart.rs` — remove UART_BASE constant
- `kernel/src/drivers/tty.rs` — remove hardcoded UART address
- `kernel/src/drivers/plic.rs` — parameterize base + context
- `kernel/src/drivers/virtio/mmio.rs` — FDT-driven slot list
- `kernel/src/drivers/virtio/blk.rs` — IRQ from slot info
- `kernel/src/drivers/virtio/net.rs` — IRQ from slot info
- `kernel/src/drivers/virtio/gpu.rs` — IRQ from slot info
- `kernel/src/drivers/virtio/input.rs` — IRQ from slot info
- `kernel/src/drivers/virtio/tablet.rs` — IRQ from slot info
- `kernel/src/arch/paging.rs` — device regions from platform info
- `kernel/src/arch/trap.rs` — timer interval, backtrace bounds
- `kernel/src/task/process.rs` — device regions in user page tables

### Resource Limits

| Limit | Value | Rationale |
|-------|-------|-----------|
| `MAX_VIRTIO_SLOTS` | 8 | Matches current QEMU virt; increase if needed |
| `MAX_RAM` | 1 GiB | Max supported RAM; bitmap = 4096 u64s = 32 KiB |
| FDT max size | 64 KiB | Sanity check; QEMU virt FDT is ~4 KiB |

Exceeding `MAX_VIRTIO_SLOTS`: extra devices silently ignored (with a
warning printed). Exceeding `MAX_RAM`: RAM beyond the limit is not used
(warning printed). FDT over 64 KiB: fall back to defaults.

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| New `platform/` module | `main.rs` (mod declaration), `platform/mod.rs`, `platform/fdt.rs` | Low (additive) |
| `kmain` signature change | `boot.S`, `main.rs` | Low (internal calling convention) |
| `frame.rs` runtime RAM range | `mm/frame.rs` | Medium — bitmap sizing changes, alloc/dealloc address math |
| UART base parameterized | `drivers/uart.rs`, `drivers/tty.rs` | Low — Uart already takes base in constructor |
| PLIC base + context parameterized | `drivers/plic.rs` | Medium — all register offset calculations change |
| VirtIO slot list from platform | `drivers/virtio/mmio.rs` | Medium — probe() and probe_all() logic changes |
| VirtIO IRQ from slot info | `drivers/virtio/blk.rs`, `net.rs`, `gpu.rs`, `input.rs`, `tablet.rs` | Low — replace formula with lookup |
| Device regions in page tables | `arch/paging.rs`, `task/process.rs` (2 functions) | Medium — hardcoded map_range calls become loops |
| Timer interval from frequency | `arch/trap.rs` | Low — const becomes runtime static |
| Backtrace bounds | `arch/trap.rs` | Low — const becomes linker symbol + platform value |
| Boot banner | `main.rs` | Low — string change |

**No cross-boundary changes**: no syscall ABI, no wire protocol, no
user-space library, no std sysroot changes.

## Acceptance Criteria

- [x] `boot.S` saves `a0`/`a1` and passes to `kmain(hart_id, dtb_ptr)`
- [x] FDT parser can extract: `/memory` reg, timebase-frequency, PLIC
      base/size, UART base/IRQ, CLINT base/size, all `virtio,mmio` nodes
- [x] `PlatformInfo` is populated from FDT at early boot
- [x] If FDT is absent (dtb_ptr=0), QEMU virt defaults are used and a
      warning is printed
- [x] No hardcoded `0x1000_0000`, `0x0C00_0000`, `0x0200_0000`,
      `0x1000_1000`, or `0x8800_0000` remain in the kernel (outside
      `platform/` default fallback and UART static initializer)
- [x] `make build` succeeds with no warnings
- [x] `make clippy` clean
- [x] System boots and reaches shell (`make run`)
- [ ] GUI mode works (`make run-gui`) — not tested (no GUI in this env)
- [ ] `mem` command shows correct RAM size — not tested (interactive)
- [ ] `kstat` counters work (timer, UART, VirtIO IRQs) — not tested (interactive)
- [x] Block devices and ext2 filesystem work
- [ ] Network works (if configured) — not tested (no tap in this env)
- [ ] `make bench` shows no regression (>20%) — not tested
- [x] FDT-parsed values match the previously hardcoded QEMU virt values
      (verified by boot log prints)

## Deferred

| Item | Rationale |
|------|-----------|
| Multi-hart boot (SBI HSM) | Requires scheduler + PLIC multi-context work |
| APLIC / AIA interrupt controller | No boards in scope use it yet |
| PCI bus / PCI VirtIO transport | Separate transport layer design needed |
| Non-16550 UART variants | Need a UART trait; out of scope for this change |
| Dynamic kernel base address | Requires linker script templating or relocation |
| Board-specific configs (compile-time) | FDT handles runtime discovery; compile-time configs can come later if needed |
| `/reserved-memory` FDT parsing | Not needed for basic operation |
| `/chosen` node parsing (bootargs etc.) | Nice-to-have, not critical |

## Implementation Notes

**FDT parser design:** The first attempt used a scan-ahead approach
(`extract_by_compatible`) that read `reg` and `interrupts` properties
by scanning forward from where `compatible` was found. This failed
because QEMU's FDT places `reg` *before* `compatible` in the property
list. Rewrote to a collect-then-process pattern: `NodeProps` struct
accumulates all properties per node during the walk, then `process_node()`
examines the complete set on `EndNode`. This is order-independent and
robust.

**UART static initializer:** `drivers/uart.rs` keeps a `const DEFAULT_BASE
= 0x1000_0000` for the compile-time static `UART` initializer. This is
needed because `platform::uart_base()` isn't available at const-init time.
The `uart::init()` function overwrites it with the FDT-discovered value.
On QEMU virt they're identical; on other boards the brief window between
boot and `uart::init()` uses the wrong address (no serial output, but
also no crash since early boot doesn't print much before platform init).

**VirtIO MMIO slot ordering:** QEMU's FDT lists VirtIO MMIO devices in
*descending* address order (0x10008000 first, 0x10001000 last). The
platform module stores them in FDT order, so callers should not assume
ascending addresses. Boot log computes min/max for display.

**PLIC context computation:** The FDT doesn't directly encode which PLIC
context maps to S-mode for a given hart. We use the standard RISC-V
convention: `context = hart_id * 2 + 1` (context 0 = M-mode hart 0,
context 1 = S-mode hart 0, etc.). This works for SiFive PLIC and
QEMU virt.

**Frame allocator bitmap:** Upsized from `[u64; 512]` (128 MiB only) to
`[u64; 4096]` (supports up to 1 GiB). The `TOTAL_FRAMES` constant
became a runtime field on `FrameAllocator`, computed from
`platform::ram_end() - platform::ram_base()`.

## Verification

**Build:** `make build` succeeds with zero warnings. `make clippy` clean
for both kernel and all user crates.

**Boot test (serial):** QEMU boots to shell. Boot log confirms all
FDT-parsed values match the previously hardcoded QEMU virt constants:

```
[platform] FDT parsed: RAM 0x80000000..0x88000000 (128 MiB)
[platform]   UART 0x10000000 IRQ 10, PLIC 0xc000000, CLINT 0x2000000
[platform]   timebase 10000000 Hz, 8 VirtIO MMIO device(s)
  128 MiB RAM, hart 0
  ...
  Mapping VirtIO: 0x10001000..0x10009000 (R+W, 8 slot(s))
  ...
[blk] Found VirtIO blk at 0x10008000 (IRQ 8)
[ext2-server] ext2: 4096 blocks, 4096 inodes, block_size=4096
rvOS shell v0.2
```

**ext2 + block device:** ext2 server connects to blk0, mounts filesystem,
shell reaches prompt — full stack working.

**Not tested (environment limitations):**
- GUI mode (`make run-gui`) — no display available
- Interactive commands (`mem`, `kstat`) — would need expect script
- Network — tap networking unavailable in this environment
- `make bench` — would need network or extended runtime
