use core::fmt;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SIZE_BITS: usize = 12;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct PhysAddr(pub usize);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct VirtAddr(pub usize);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct PhysPageNum(pub usize);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct VirtPageNum(pub usize);

// PhysAddr conversions
impl PhysAddr {
    pub fn page_number(&self) -> PhysPageNum {
        PhysPageNum(self.0 / PAGE_SIZE)
    }
    pub fn page_offset(&self) -> usize {
        self.0 & (PAGE_SIZE - 1)
    }
    pub fn aligned(&self) -> bool {
        self.page_offset() == 0
    }
    pub fn floor(&self) -> PhysPageNum {
        PhysPageNum(self.0 / PAGE_SIZE)
    }
    pub fn ceil(&self) -> PhysPageNum {
        PhysPageNum(self.0.div_ceil(PAGE_SIZE))
    }
}

impl From<usize> for PhysAddr {
    fn from(v: usize) -> Self {
        PhysAddr(v)
    }
}

impl From<PhysAddr> for usize {
    fn from(pa: PhysAddr) -> Self {
        pa.0
    }
}

impl From<PhysPageNum> for PhysAddr {
    fn from(ppn: PhysPageNum) -> Self {
        PhysAddr(ppn.0 << PAGE_SIZE_BITS)
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}

// VirtAddr conversions
impl VirtAddr {
    pub fn page_number(&self) -> VirtPageNum {
        VirtPageNum(self.0 / PAGE_SIZE)
    }
    pub fn page_offset(&self) -> usize {
        self.0 & (PAGE_SIZE - 1)
    }
    pub fn aligned(&self) -> bool {
        self.page_offset() == 0
    }
    pub fn floor(&self) -> VirtPageNum {
        VirtPageNum(self.0 / PAGE_SIZE)
    }
    pub fn ceil(&self) -> VirtPageNum {
        VirtPageNum(self.0.div_ceil(PAGE_SIZE))
    }
    /// Extract the three Sv39 VPN indices
    pub fn vpn_indices(&self) -> [usize; 3] {
        let vpn = self.0 >> PAGE_SIZE_BITS;
        [
            vpn & 0x1FF,  // VPN[0]
            (vpn >> 9) & 0x1FF,  // VPN[1]
            (vpn >> 18) & 0x1FF, // VPN[2]
        ]
    }
}

impl From<usize> for VirtAddr {
    fn from(v: usize) -> Self {
        VirtAddr(v)
    }
}

impl From<VirtAddr> for usize {
    fn from(va: VirtAddr) -> Self {
        va.0
    }
}

impl From<VirtPageNum> for VirtAddr {
    fn from(vpn: VirtPageNum) -> Self {
        VirtAddr(vpn.0 << PAGE_SIZE_BITS)
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VirtAddr({:#x})", self.0)
    }
}

// PhysPageNum conversions
impl PhysPageNum {
    pub fn addr(&self) -> PhysAddr {
        PhysAddr(self.0 << PAGE_SIZE_BITS)
    }
    /// Get a mutable pointer to the start of this physical page
    pub fn as_mut_ptr(&self) -> *mut u8 {
        (self.0 << PAGE_SIZE_BITS) as *mut u8
    }
    /// Get a reference to the page as a specific type
    pub fn as_page_table(&self) -> &'static mut [PageTableEntry; 512] {
        unsafe { &mut *((self.0 << PAGE_SIZE_BITS) as *mut [PageTableEntry; 512]) }
    }
    /// Zero the entire physical page
    pub fn zero_page(&self) {
        let ptr = self.as_mut_ptr();
        unsafe {
            core::ptr::write_bytes(ptr, 0, PAGE_SIZE);
        }
    }
}

impl From<usize> for PhysPageNum {
    fn from(v: usize) -> Self {
        PhysPageNum(v)
    }
}

impl From<PhysPageNum> for usize {
    fn from(ppn: PhysPageNum) -> Self {
        ppn.0
    }
}

impl fmt::Debug for PhysPageNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PhysPageNum({:#x})", self.0)
    }
}

// VirtPageNum conversions
impl VirtPageNum {
    pub fn addr(&self) -> VirtAddr {
        VirtAddr(self.0 << PAGE_SIZE_BITS)
    }
    /// Extract the three Sv39 VPN indices
    pub fn indices(&self) -> [usize; 3] {
        [
            self.0 & 0x1FF,  // VPN[0]
            (self.0 >> 9) & 0x1FF,  // VPN[1]
            (self.0 >> 18) & 0x1FF, // VPN[2]
        ]
    }
}

impl From<usize> for VirtPageNum {
    fn from(v: usize) -> Self {
        VirtPageNum(v)
    }
}

impl From<VirtPageNum> for usize {
    fn from(vpn: VirtPageNum) -> Self {
        vpn.0
    }
}

impl fmt::Debug for VirtPageNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VirtPageNum({:#x})", self.0)
    }
}

// PageTableEntry used by PhysPageNum::as_page_table
use crate::mm::page_table::PageTableEntry;
