use crate::task::context::TaskContext;
use crate::mm::address::PAGE_SIZE;
use crate::mm::frame;
use core::sync::atomic::{AtomicUsize, Ordering};

const KERNEL_STACK_PAGES: usize = 4; // 16 KiB
const KERNEL_STACK_SIZE: usize = KERNEL_STACK_PAGES * PAGE_SIZE;

pub const MAX_PROCS: usize = 64;
const NAME_LEN: usize = 16;

static NEXT_PID: AtomicUsize = AtomicUsize::new(1);

fn alloc_pid() -> usize {
    NEXT_PID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Ready,
    Running,
    Blocked,
    Dead,
}

pub struct Process {
    pub pid: usize,
    pub state: ProcessState,
    pub context: TaskContext,
    pub kernel_stack_base: usize,
    pub kernel_stack_top: usize,
    name: [u8; NAME_LEN],
    name_len: usize,
}

impl Process {
    /// Create a new kernel task with the given entry function
    pub fn new_kernel(entry: fn()) -> Self {
        let pid = alloc_pid();

        let stack_ppn = frame::frame_alloc_contiguous(KERNEL_STACK_PAGES)
            .expect("Failed to allocate kernel stack");
        let stack_base = stack_ppn.0 * PAGE_SIZE;
        let stack_top = stack_base + KERNEL_STACK_SIZE;

        let context = TaskContext::new(entry as usize, stack_top);

        Process {
            pid,
            state: ProcessState::Ready,
            context,
            kernel_stack_base: stack_base,
            kernel_stack_top: stack_top,
            name: [0u8; NAME_LEN],
            name_len: 0,
        }
    }

    /// Create a "dummy" process representing the boot/idle task (PID 0)
    pub fn new_idle() -> Self {
        let mut p = Process {
            pid: 0,
            state: ProcessState::Running,
            context: TaskContext::zero(),
            kernel_stack_base: 0,
            kernel_stack_top: 0,
            name: [0u8; NAME_LEN],
            name_len: 0,
        };
        p.set_name("idle");
        p
    }

    pub fn set_name(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(NAME_LEN);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len;
    }

    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("???")
    }
}
