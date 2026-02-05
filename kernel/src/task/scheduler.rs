use alloc::collections::VecDeque;
use alloc::vec::Vec;
use alloc::string::String;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::sync::SpinLock;
use crate::task::context::TaskContext;
use crate::task::process::{Process, ProcessState, MAX_PROCS, USER_CODE_BASE, USER_STACK_TOP};

extern "C" {
    fn switch_context(old: *mut TaskContext, new: *const TaskContext);
}

struct Scheduler {
    processes: Vec<Option<Process>>,
    ready_queue: VecDeque<usize>,
    current: usize, // PID of current process
    initialized: bool,
}

impl Scheduler {
    const fn new() -> Self {
        Scheduler {
            processes: Vec::new(),
            ready_queue: VecDeque::new(),
            current: 0,
            initialized: false,
        }
    }

    fn init(&mut self) {
        self.processes = Vec::with_capacity(MAX_PROCS);
        for _ in 0..MAX_PROCS {
            self.processes.push(None);
        }

        // Create idle process (PID 0) - represents the boot thread
        let idle = Process::new_idle();
        self.processes[0] = Some(idle);
        self.current = 0;
        self.initialized = true;
    }
}

static SCHEDULER: SpinLock<Scheduler> = SpinLock::new(Scheduler::new());

/// Stored kernel satp value for restoring after user process trap
static KERNEL_SATP: AtomicUsize = AtomicUsize::new(0);

pub fn init() {
    SCHEDULER.lock().init();
    crate::println!("Scheduler initialized (max {} processes)", MAX_PROCS);
}

/// Save the kernel's satp value (call this after enabling paging)
pub fn save_kernel_satp() {
    let satp: usize = crate::read_csr!("satp");
    KERNEL_SATP.store(satp, Ordering::Relaxed);
}

/// Spawn a new kernel task. Returns the PID.
pub fn spawn(entry: fn()) -> usize {
    let mut sched = SCHEDULER.lock();
    let proc = Process::new_kernel(entry);
    let pid = proc.pid;

    if pid < MAX_PROCS {
        if sched.processes.len() <= pid {
            while sched.processes.len() <= pid {
                sched.processes.push(None);
            }
        }
        sched.processes[pid] = Some(proc);
        sched.ready_queue.push_back(pid);
    } else {
        panic!("Too many processes (max {})", MAX_PROCS);
    }

    pid
}

/// Spawn with a name for display purposes
pub fn spawn_named(entry: fn(), name: &str) -> usize {
    let pid = spawn(entry);
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes[pid] {
        proc.set_name(name);
    }
    crate::println!("  Spawned [{}] \"{}\" (PID {})", pid, name, pid);
    pid
}

/// Spawn a user-mode process from machine code bytes. Returns the PID.
pub fn spawn_user(user_code: &[u8], name: &str) -> usize {
    let mut sched = SCHEDULER.lock();
    let mut proc = Process::new_user(user_code);
    let pid = proc.pid;
    proc.set_name(name);

    if pid < MAX_PROCS {
        if sched.processes.len() <= pid {
            while sched.processes.len() <= pid {
                sched.processes.push(None);
            }
        }
        sched.processes[pid] = Some(proc);
        sched.ready_queue.push_back(pid);
    } else {
        panic!("Too many processes (max {})", MAX_PROCS);
    }

    crate::println!("  Spawned user [{}] \"{}\" (PID {})", pid, name, pid);
    pid
}

/// Get current PID
pub fn current_pid() -> usize {
    SCHEDULER.lock().current
}

/// Yield the current task and schedule the next one.
pub fn schedule() {
    let mut sched = SCHEDULER.lock();
    if !sched.initialized || sched.ready_queue.is_empty() {
        return;
    }

    let old_pid = sched.current;

    let next_pid = match sched.ready_queue.pop_front() {
        Some(pid) => pid,
        None => return,
    };

    if next_pid == old_pid {
        sched.ready_queue.push_back(next_pid);
        return;
    }

    // Put old task back in ready queue (if it's still running)
    if let Some(ref mut old_proc) = sched.processes[old_pid] {
        if old_proc.state == ProcessState::Running {
            old_proc.state = ProcessState::Ready;
            sched.ready_queue.push_back(old_pid);
        }
    }

    // Set new task as running
    if let Some(ref mut new_proc) = sched.processes[next_pid] {
        new_proc.state = ProcessState::Running;
    }

    sched.current = next_pid;

    let old_ctx = &mut sched.processes[old_pid].as_mut().unwrap().context as *mut TaskContext;
    let new_ctx = &sched.processes[next_pid].as_ref().unwrap().context as *const TaskContext;

    // Drop the lock BEFORE switching (critical!)
    drop(sched);

    unsafe {
        switch_context(old_ctx, new_ctx);
    }

    // After switch_context returns, we've been switched BACK to this task.
    // Re-enable interrupts in case we were switched from inside a trap handler
    // (where sstatus.SIE was cleared by hardware on trap entry).
    crate::arch::csr::enable_interrupts();
}

/// Mark the current task as dead and schedule away (for kernel tasks)
pub fn exit_current() -> ! {
    {
        let mut sched = SCHEDULER.lock();
        let pid = sched.current;
        if let Some(ref mut proc) = sched.processes[pid] {
            proc.state = ProcessState::Dead;
        }
    }
    schedule();
    unreachable!("exit_current: schedule returned to dead task");
}

/// Mark current task as dead (called from syscall context, may return)
pub fn exit_current_from_syscall() {
    {
        let mut sched = SCHEDULER.lock();
        let pid = sched.current;
        if let Some(ref mut proc) = sched.processes[pid] {
            proc.state = ProcessState::Dead;
        }
    }
    schedule();
}

/// Set a process to Blocked state
pub fn block_process(pid: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        proc.state = ProcessState::Blocked;
    }
}

/// Wake a blocked process (set to Ready and add to ready queue)
pub fn wake_process(pid: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        if proc.state == ProcessState::Blocked {
            proc.state = ProcessState::Ready;
            sched.ready_queue.push_back(pid);
        }
    }
}

/// Return a formatted string listing all processes
pub fn process_list() -> String {
    let sched = SCHEDULER.lock();
    let mut out = String::new();
    let _ = writeln!(out, "  PID  STATE     NAME");
    let _ = writeln!(out, "  ---  --------  ----------------");
    for (i, slot) in sched.processes.iter().enumerate() {
        if let Some(proc) = slot {
            let state = match proc.state {
                ProcessState::Ready => "Ready   ",
                ProcessState::Running => "Running ",
                ProcessState::Blocked => "Blocked ",
                ProcessState::Dead => "Dead    ",
            };
            let _ = writeln!(out, "  {:3}  {}  {}", i, state, proc.name());
        }
    }
    out
}

/// Count alive (non-Dead) processes
pub fn alive_count() -> usize {
    let sched = SCHEDULER.lock();
    sched.processes.iter().filter(|slot| {
        matches!(slot, Some(p) if p.state != ProcessState::Dead)
    }).count()
}

/// Check if a specific PID is alive
pub fn is_alive(pid: usize) -> bool {
    let sched = SCHEDULER.lock();
    matches!(
        sched.processes.get(pid),
        Some(Some(p)) if p.state != ProcessState::Dead
    )
}

/// FFI-safe struct for returning user process info to assembly trampoline.
#[repr(C)]
pub struct UserReturnInfo {
    pub satp: usize,
    pub sepc: usize,
    pub user_sp: usize,
    pub kernel_sp: usize,
}

/// Called from user_entry_trampoline (in switch.S) to get the info needed
/// to sret into user mode. Takes a pointer to a UserReturnInfo struct
/// and fills it in (the struct is too large for register return on rv64).
#[no_mangle]
pub extern "C" fn prepare_user_return(out: *mut UserReturnInfo) {
    let sched = SCHEDULER.lock();
    let pid = sched.current;
    let proc = sched.processes[pid].as_ref().expect("prepare_user_return: no current process");
    unsafe {
        (*out).satp = proc.user_satp;
        (*out).sepc = USER_CODE_BASE;
        (*out).user_sp = USER_STACK_TOP;
        (*out).kernel_sp = proc.kernel_stack_top;
    }
}

/// Called from trap.S (_from_user path) to switch to kernel page table
/// before running the trap handler. This ensures kernel data structures
/// are accessible with the kernel's page table.
#[no_mangle]
pub extern "C" fn restore_kernel_satp_asm() {
    let satp = KERNEL_SATP.load(Ordering::Relaxed);
    if satp != 0 {
        unsafe {
            core::arch::asm!(
                "csrw satp, {0}",
                "sfence.vma",
                in(reg) satp,
            );
        }
    }
}

/// Called from trap.S before returning to user mode to get the
/// current process's user satp. Returns 0 if current process is not a user process.
#[no_mangle]
pub extern "C" fn get_current_user_satp() -> usize {
    let sched = SCHEDULER.lock();
    let pid = sched.current;
    match sched.processes[pid].as_ref() {
        Some(proc) if proc.is_user => proc.user_satp,
        _ => 0,
    }
}
