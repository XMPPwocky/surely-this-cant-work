//! Minimal Flattened Device Tree (FDT) parser.
//!
//! No-alloc, operates on a `&[u8]` slice of the raw DTB.  Extracts only
//! what the kernel needs: memory regions, device addresses, IRQ numbers,
//! and timer frequency.

use super::{PlatformInfo, MemRegion, VirtioMmioSlot, MAX_VIRTIO_SLOTS};

// ── FDT constants ────────────────────────────────────────────────────

pub const FDT_MAGIC: u32 = 0xd00d_feed;

const FDT_BEGIN_NODE: u32 = 0x0000_0001;
const FDT_END_NODE: u32   = 0x0000_0002;
const FDT_PROP: u32        = 0x0000_0003;
const FDT_NOP: u32         = 0x0000_0004;
const FDT_END: u32         = 0x0000_0009;

// ── Helpers ──────────────────────────────────────────────────────────

fn be_u32(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// Align `off` up to the next multiple of 4.
fn align4(off: usize) -> usize {
    (off + 3) & !3
}

/// Read a big-endian cell value (`cells` × 4 bytes).  Returns u64.
fn read_cells(data: &[u8], off: usize, cells: u32) -> u64 {
    match cells {
        1 => be_u32(data, off) as u64,
        2 => ((be_u32(data, off) as u64) << 32) | (be_u32(data, off + 4) as u64),
        _ => 0,
    }
}

/// Check if a null-terminated string list (FDT compatible property) contains `needle`.
fn stringlist_contains(data: &[u8], needle: &[u8]) -> bool {
    let mut start = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == 0 {
            if &data[start..i] == needle {
                return true;
            }
            start = i + 1;
        }
    }
    false
}

// ── FDT walker ───────────────────────────────────────────────────────

/// Low-level walker state: position in the structure block.
struct Walker<'a> {
    data: &'a [u8],
    off_struct: usize,
    off_strings: usize,
    pos: usize,
}

/// What the walker yielded.
enum Token<'a> {
    BeginNode { name: &'a [u8], after: usize },
    EndNode { after: usize },
    Prop { name_off: u32, value: &'a [u8], after: usize },
    End,
}

impl<'a> Walker<'a> {
    fn new(data: &'a [u8], off_struct: usize, off_strings: usize) -> Self {
        Walker { data, off_struct, off_strings, pos: off_struct }
    }

    fn next(&mut self) -> Token<'a> {
        loop {
            if self.pos + 4 > self.data.len() {
                return Token::End;
            }
            let tag = be_u32(self.data, self.pos);
            self.pos += 4;

            match tag {
                FDT_BEGIN_NODE => {
                    let name_start = self.pos;
                    // Find the null terminator
                    let mut end = name_start;
                    while end < self.data.len() && self.data[end] != 0 {
                        end += 1;
                    }
                    let name = &self.data[name_start..end];
                    self.pos = align4(end + 1); // skip null + align
                    let after = self.pos;
                    return Token::BeginNode { name, after };
                }
                FDT_END_NODE => {
                    let after = self.pos;
                    return Token::EndNode { after };
                }
                FDT_PROP => {
                    let len = be_u32(self.data, self.pos) as usize;
                    let name_off = be_u32(self.data, self.pos + 4);
                    self.pos += 8;
                    let value = &self.data[self.pos..self.pos + len];
                    self.pos = align4(self.pos + len);
                    let after = self.pos;
                    return Token::Prop { name_off, value, after };
                }
                FDT_NOP => continue,
                FDT_END => return Token::End,
                _ => return Token::End, // malformed
            }
        }
    }

    /// Look up a string in the strings block by offset.
    fn string_at(&self, off: u32) -> &'a [u8] {
        let start = self.off_strings + off as usize;
        let mut end = start;
        while end < self.data.len() && self.data[end] != 0 {
            end += 1;
        }
        &self.data[start..end]
    }

    fn reset(&mut self) {
        self.pos = self.off_struct;
    }
}

// ── High-level extraction ────────────────────────────────────────────

/// Parse an FDT blob and extract platform information.
///
/// Returns `None` if the FDT is malformed or missing critical nodes.
pub fn parse_platform_info(dtb: &[u8], hart_id: usize) -> Option<PlatformInfo> {
    // ── Validate header ──────────────────────────────────────────────
    if dtb.len() < 40 {
        return None;
    }
    let magic = be_u32(dtb, 0);
    if magic != FDT_MAGIC {
        return None;
    }
    let off_struct = be_u32(dtb, 8) as usize;
    let off_strings = be_u32(dtb, 12) as usize;
    let boot_cpuid = be_u32(dtb, 28);

    let mut info = PlatformInfo {
        ram: MemRegion { base: 0, size: 0 },
        boot_hart_id: hart_id,
        timebase_frequency: 0,
        plic_base: 0,
        plic_size: 0,
        plic_context: 0,
        uart_base: 0,
        uart_irq: 0,
        clint_base: 0,
        clint_size: 0,
        virtio_mmio: [VirtioMmioSlot { base: 0, irq: 0 }; MAX_VIRTIO_SLOTS],
        virtio_mmio_count: 0,
    };

    let mut w = Walker::new(dtb, off_struct, off_strings);

    // ── Pass 1: Find root-level #address-cells and #size-cells ───────
    // Defaults per spec: address-cells=2, size-cells=1
    let mut root_addr_cells: u32 = 2;
    let mut root_size_cells: u32 = 1;
    find_root_cells(&mut w, &mut root_addr_cells, &mut root_size_cells);

    // ── Pass 2: Walk the tree extracting what we need ────────────────
    w.reset();
    let mut depth: usize = 0;
    // Track #address-cells/#size-cells per depth (max depth 8)
    let mut addr_cells_stack: [u32; 8] = [root_addr_cells; 8];
    let mut size_cells_stack: [u32; 8] = [root_size_cells; 8];
    // Current node name at each depth for path matching
    let mut node_names: [&[u8]; 8] = [b""; 8];

    loop {
        let tok = w.next();
        match tok {
            Token::BeginNode { name, .. } => {
                depth += 1;
                if depth < 8 {
                    node_names[depth] = name;
                    // Inherit parent's cells
                    addr_cells_stack[depth] = addr_cells_stack[depth.saturating_sub(1)];
                    size_cells_stack[depth] = size_cells_stack[depth.saturating_sub(1)];
                }
            }
            Token::EndNode { .. } => {
                depth = depth.saturating_sub(1);
            }
            Token::Prop { name_off, value, .. } => {
                let prop_name = w.string_at(name_off);
                let d = if depth < 8 { depth } else { continue };

                // Track #address-cells / #size-cells
                if prop_name == b"#address-cells" && value.len() >= 4 {
                    addr_cells_stack[d] = be_u32(value, 0);
                    continue;
                }
                if prop_name == b"#size-cells" && value.len() >= 4 {
                    size_cells_stack[d] = be_u32(value, 0);
                    continue;
                }

                // ── /memory node ─────────────────────────────────────
                if prop_name == b"device_type" && value.starts_with(b"memory") && info.ram.size == 0 {
                    // The `reg` property is on the same node — keep scanning
                }
                if prop_name == b"reg" && d >= 1 && node_name_starts_with(node_names[d], b"memory") {
                    let parent_d = d.saturating_sub(1);
                    let ac = addr_cells_stack[parent_d];
                    let sc = size_cells_stack[parent_d];
                    let cell_bytes = (ac + sc) as usize * 4;
                    if value.len() >= cell_bytes {
                        info.ram.base = read_cells(value, 0, ac) as usize;
                        info.ram.size = read_cells(value, ac as usize * 4, sc) as usize;
                    }
                    continue;
                }

                // ── /cpus/timebase-frequency ─────────────────────────
                if prop_name == b"timebase-frequency" {
                    if d >= 1 && node_names[d] == b"cpus" {
                        info.timebase_frequency = if value.len() >= 8 {
                            ((be_u32(value, 0) as u64) << 32) | be_u32(value, 4) as u64
                        } else if value.len() >= 4 {
                            be_u32(value, 0) as u64
                        } else {
                            0
                        };
                    }
                    continue;
                }

                // ── compatible-based matching ────────────────────────
                if prop_name == b"compatible" {
                    let parent_d = d.saturating_sub(1);
                    let ac = addr_cells_stack[parent_d];
                    let sc = size_cells_stack[parent_d];
                    extract_by_compatible(&mut w, &mut info, value, ac, sc, boot_cpuid, hart_id);
                    continue;
                }
            }
            Token::End => break,
        }
    }

    // ── Compute PLIC context ─────────────────────────────────────────
    // On most RISC-V platforms with SBI, the boot hart's S-mode PLIC
    // context is (hart_id * 2) + 1 (context 0 = M-mode, 1 = S-mode,
    // 2 = hart1 M-mode, 3 = hart1 S-mode, ...).
    if info.plic_base != 0 && info.plic_context == 0 {
        info.plic_context = (hart_id as u32) * 2 + 1;
    }

    // ── Sanity check ─────────────────────────────────────────────────
    if info.ram.size == 0 || info.timebase_frequency == 0 {
        return None;
    }

    Some(info)
}

/// Scan the root node for #address-cells and #size-cells.
fn find_root_cells(w: &mut Walker<'_>, addr_cells: &mut u32, size_cells: &mut u32) {
    // The first BEGIN_NODE is the root ("/").  Read its properties until
    // END_NODE or the next BEGIN_NODE (child).
    loop {
        let tok = w.next();
        match tok {
            Token::BeginNode { .. } => {
                // Either the root node itself (first hit) or a child.
                // Read properties at this level.
                loop {
                    let tok2 = w.next();
                    match tok2 {
                        Token::Prop { name_off, value, .. } => {
                            let name = w.string_at(name_off);
                            if name == b"#address-cells" && value.len() >= 4 {
                                *addr_cells = be_u32(value, 0);
                            }
                            if name == b"#size-cells" && value.len() >= 4 {
                                *size_cells = be_u32(value, 0);
                            }
                        }
                        Token::BeginNode { .. } | Token::EndNode { .. } | Token::End => return,
                    }
                }
            }
            Token::End => return,
            _ => {}
        }
    }
}

/// When we encounter a `compatible` property, check if it matches any
/// device we're looking for and extract the relevant info.
///
/// This is called while the walker is positioned just after the
/// `compatible` prop.  We need to scan forward for sibling properties
/// (`reg`, `interrupts`, etc.) within the same node, then restore the
/// walker position.  Since we do a single forward pass, we instead store
/// what we found and let the main loop continue collecting properties.
///
/// To avoid a second pass, we use a simpler approach: after seeing
/// `compatible`, we scan ahead within the same node to collect the reg
/// and interrupts properties.
fn extract_by_compatible(
    w: &mut Walker<'_>,
    info: &mut PlatformInfo,
    compat_value: &[u8],
    addr_cells: u32,
    size_cells: u32,
    _boot_cpuid: u32,
    _hart_id: usize,
) {
    // Determine what we're looking at
    let is_plic = stringlist_contains(compat_value, b"riscv,plic0")
        || stringlist_contains(compat_value, b"sifive,plic-1.0.0");
    let is_clint = stringlist_contains(compat_value, b"riscv,clint0")
        || stringlist_contains(compat_value, b"sifive,clint0");
    let is_uart = stringlist_contains(compat_value, b"ns16550a")
        || stringlist_contains(compat_value, b"ns16550");
    let is_virtio = stringlist_contains(compat_value, b"virtio,mmio");

    if !is_plic && !is_clint && !is_uart && !is_virtio {
        return;
    }

    // Scan ahead for reg and interrupts properties within this node
    let mut reg_base: usize = 0;
    let mut reg_size: usize = 0;
    let mut irq: u32 = 0;
    let mut found_reg = false;

    // Save position so we can scan ahead, then the main loop continues
    // from where we leave off.  Since the main loop's own matching for
    // this node's properties would need the walker advanced past them
    // anyway, we just consume them here.
    let mut sub_depth: usize = 0;
    loop {
        let tok = w.next();
        match tok {
            Token::Prop { name_off, value, .. } => {
                if sub_depth > 0 { continue; }
                let pname = w.string_at(name_off);
                if pname == b"reg" {
                    let cell_bytes = (addr_cells + size_cells) as usize * 4;
                    if value.len() >= cell_bytes {
                        reg_base = read_cells(value, 0, addr_cells) as usize;
                        reg_size = read_cells(value, addr_cells as usize * 4, size_cells) as usize;
                        found_reg = true;
                    }
                } else if pname == b"interrupts" && value.len() >= 4 {
                    irq = be_u32(value, 0);
                }
            }
            Token::BeginNode { .. } => { sub_depth += 1; }
            Token::EndNode { .. } => {
                if sub_depth == 0 {
                    // We've consumed this node's END_NODE.  The main loop
                    // will see the next token after it.
                    break;
                }
                sub_depth -= 1;
            }
            Token::End => break,
        }
    }

    if !found_reg {
        return;
    }

    if is_plic && info.plic_base == 0 {
        info.plic_base = reg_base;
        info.plic_size = reg_size;
    } else if is_clint && info.clint_base == 0 {
        info.clint_base = reg_base;
        info.clint_size = reg_size;
    } else if is_uart && info.uart_base == 0 {
        info.uart_base = reg_base;
        info.uart_irq = irq;
    } else if is_virtio && info.virtio_mmio_count < MAX_VIRTIO_SLOTS {
        let idx = info.virtio_mmio_count;
        info.virtio_mmio[idx] = VirtioMmioSlot { base: reg_base, irq };
        info.virtio_mmio_count += 1;
    }
}

fn node_name_starts_with(name: &[u8], prefix: &[u8]) -> bool {
    if name.len() < prefix.len() {
        return false;
    }
    if &name[..prefix.len()] != prefix {
        return false;
    }
    // After the prefix there should be either nothing, '@', or end of string
    name.len() == prefix.len() || name[prefix.len()] == b'@'
}
