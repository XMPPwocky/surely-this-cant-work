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

fn node_name_starts_with(name: &[u8], prefix: &[u8]) -> bool {
    if name.len() < prefix.len() {
        return false;
    }
    if &name[..prefix.len()] != prefix {
        return false;
    }
    name.len() == prefix.len() || name[prefix.len()] == b'@'
}

// ── FDT walker ───────────────────────────────────────────────────────

/// Low-level walker state: position in the structure block.
struct Walker<'a> {
    data: &'a [u8],
    #[allow(dead_code)]
    off_struct: usize,
    off_strings: usize,
    pos: usize,
}

/// What the walker yielded.
enum Token<'a> {
    BeginNode { name: &'a [u8] },
    EndNode,
    Prop { name_off: u32, value: &'a [u8] },
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
                    let mut end = name_start;
                    while end < self.data.len() && self.data[end] != 0 {
                        end += 1;
                    }
                    let name = &self.data[name_start..end];
                    self.pos = align4(end + 1);
                    return Token::BeginNode { name };
                }
                FDT_END_NODE => return Token::EndNode,
                FDT_PROP => {
                    let len = be_u32(self.data, self.pos) as usize;
                    let name_off = be_u32(self.data, self.pos + 4);
                    self.pos += 8;
                    let value = &self.data[self.pos..self.pos + len];
                    self.pos = align4(self.pos + len);
                    return Token::Prop { name_off, value };
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
}

// ── Per-node property accumulator ────────────────────────────────────

/// Collects the properties we care about for a single FDT node.
/// Processed when we hit END_NODE (i.e., after ALL properties are seen).
struct NodeProps<'a> {
    name: &'a [u8],
    compatible: &'a [u8],
    device_type: &'a [u8],
    reg: &'a [u8],
    interrupts: &'a [u8],
    timebase_frequency: &'a [u8],
    addr_cells: Option<u32>,
    size_cells: Option<u32>,
}

impl<'a> NodeProps<'a> {
    fn new(name: &'a [u8]) -> Self {
        NodeProps {
            name,
            compatible: b"",
            device_type: b"",
            reg: b"",
            interrupts: b"",
            timebase_frequency: b"",
            addr_cells: None,
            size_cells: None,
        }
    }
}

// ── High-level extraction ────────────────────────────────────────────

/// Parse an FDT blob and extract platform information.
///
/// Returns `None` if the FDT is malformed or missing critical nodes.
pub fn parse_platform_info(dtb: &[u8], hart_id: usize) -> Option<PlatformInfo> {
    if dtb.len() < 40 {
        return None;
    }
    let magic = be_u32(dtb, 0);
    if magic != FDT_MAGIC {
        return None;
    }
    let off_struct = be_u32(dtb, 8) as usize;
    let off_strings = be_u32(dtb, 12) as usize;

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

    // ── Walk the tree ────────────────────────────────────────────────
    //
    // Strategy: maintain a stack of NodeProps.  On BEGIN_NODE, push.
    // On PROP, record into the current node.  On END_NODE, process the
    // completed node and pop.
    //
    // We use a fixed-size stack (max depth 8) to avoid allocation.

    const MAX_DEPTH: usize = 8;
    // Stack of (node_props, parent_addr_cells, parent_size_cells)
    let mut stack: [Option<NodeProps<'_>>; MAX_DEPTH] = [const { None }; MAX_DEPTH];
    let mut depth: usize = 0;

    // Track inherited #address-cells / #size-cells per depth.
    // Defaults per DT spec: address-cells=2, size-cells=1
    let mut addr_cells: [u32; MAX_DEPTH] = [2; MAX_DEPTH];
    let mut size_cells: [u32; MAX_DEPTH] = [1; MAX_DEPTH];

    loop {
        let tok = w.next();
        match tok {
            Token::BeginNode { name } => {
                if depth < MAX_DEPTH {
                    stack[depth] = Some(NodeProps::new(name));
                    // Inherit parent's cells (will be overridden if this
                    // node has its own #address-cells/#size-cells props)
                    if depth > 0 {
                        addr_cells[depth] = addr_cells[depth - 1];
                        size_cells[depth] = size_cells[depth - 1];
                    }
                }
                depth += 1;
            }
            Token::Prop { name_off, value } => {
                // d = index into our stack (depth-1, clamped)
                if depth == 0 || depth > MAX_DEPTH { continue; }
                let d = depth - 1;
                let pname = w.string_at(name_off);
                if let Some(ref mut node) = stack[d] {
                    if pname == b"compatible" {
                        node.compatible = value;
                    } else if pname == b"device_type" {
                        node.device_type = value;
                    } else if pname == b"reg" {
                        node.reg = value;
                    } else if pname == b"interrupts" {
                        node.interrupts = value;
                    } else if pname == b"timebase-frequency" {
                        node.timebase_frequency = value;
                    } else if pname == b"#address-cells" && value.len() >= 4 {
                        let v = be_u32(value, 0);
                        node.addr_cells = Some(v);
                        addr_cells[d] = v;
                    } else if pname == b"#size-cells" && value.len() >= 4 {
                        let v = be_u32(value, 0);
                        node.size_cells = Some(v);
                        size_cells[d] = v;
                    }
                }
            }
            Token::EndNode => {
                depth = depth.saturating_sub(1);
                if depth < MAX_DEPTH {
                    if let Some(node) = stack[depth].take() {
                        // Parent's #address-cells/#size-cells determine how
                        // to decode this node's `reg` property.
                        let parent_ac = if depth > 0 { addr_cells[depth - 1] } else { 2 };
                        let parent_sc = if depth > 0 { size_cells[depth - 1] } else { 1 };
                        process_node(&node, parent_ac, parent_sc, depth, &mut info);
                    }
                }
            }
            Token::End => break,
        }
    }

    // ── Compute PLIC context ─────────────────────────────────────────
    // On RISC-V with SBI: boot hart S-mode context = hart_id * 2 + 1
    if info.plic_base != 0 && info.plic_context == 0 {
        info.plic_context = (hart_id as u32) * 2 + 1;
    }

    // ── Sanity check ─────────────────────────────────────────────────
    if info.ram.size == 0 || info.timebase_frequency == 0 {
        return None;
    }

    Some(info)
}

/// Process a completed node's accumulated properties.
fn process_node(
    node: &NodeProps<'_>,
    parent_ac: u32,
    parent_sc: u32,
    depth: usize,
    info: &mut PlatformInfo,
) {
    // ── /memory node (identified by device_type or node name) ────────
    if (node.device_type.starts_with(b"memory") || node_name_starts_with(node.name, b"memory"))
        && !node.reg.is_empty()
        && info.ram.size == 0
    {
        let cell_bytes = (parent_ac + parent_sc) as usize * 4;
        if node.reg.len() >= cell_bytes {
            info.ram.base = read_cells(node.reg, 0, parent_ac) as usize;
            info.ram.size = read_cells(node.reg, parent_ac as usize * 4, parent_sc) as usize;
        }
        return;
    }

    // ── /cpus node (timebase-frequency) ──────────────────────────────
    if node.name == b"cpus" && !node.timebase_frequency.is_empty() {
        let v = node.timebase_frequency;
        info.timebase_frequency = if v.len() >= 8 {
            ((be_u32(v, 0) as u64) << 32) | be_u32(v, 4) as u64
        } else if v.len() >= 4 {
            be_u32(v, 0) as u64
        } else {
            0
        };
        return;
    }

    // ── compatible-based matching ────────────────────────────────────
    if node.compatible.is_empty() {
        return;
    }

    // Parse reg (base, size) using parent's cells
    let mut reg_base: usize = 0;
    let mut reg_size: usize = 0;
    if !node.reg.is_empty() {
        let cell_bytes = (parent_ac + parent_sc) as usize * 4;
        if node.reg.len() >= cell_bytes {
            reg_base = read_cells(node.reg, 0, parent_ac) as usize;
            reg_size = read_cells(node.reg, parent_ac as usize * 4, parent_sc) as usize;
        }
    }

    // Parse interrupts (first cell = IRQ number)
    let irq = if node.interrupts.len() >= 4 {
        be_u32(node.interrupts, 0)
    } else {
        0
    };

    let _ = depth; // could use for path filtering if needed

    let c = node.compatible;

    // PLIC
    if (stringlist_contains(c, b"riscv,plic0") || stringlist_contains(c, b"sifive,plic-1.0.0"))
        && info.plic_base == 0 && reg_base != 0
    {
        info.plic_base = reg_base;
        info.plic_size = reg_size;
        return;
    }

    // CLINT
    if (stringlist_contains(c, b"riscv,clint0") || stringlist_contains(c, b"sifive,clint0"))
        && info.clint_base == 0 && reg_base != 0
    {
        info.clint_base = reg_base;
        info.clint_size = reg_size;
        return;
    }

    // UART (NS16550)
    if (stringlist_contains(c, b"ns16550a") || stringlist_contains(c, b"ns16550"))
        && info.uart_base == 0 && reg_base != 0
    {
        info.uart_base = reg_base;
        info.uart_irq = irq;
        return;
    }

    // VirtIO MMIO
    if stringlist_contains(c, b"virtio,mmio")
        && info.virtio_mmio_count < MAX_VIRTIO_SLOTS && reg_base != 0
    {
        let idx = info.virtio_mmio_count;
        info.virtio_mmio[idx] = VirtioMmioSlot { base: reg_base, irq };
        info.virtio_mmio_count += 1;
    }
}
