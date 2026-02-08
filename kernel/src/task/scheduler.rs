use alloc::collections::VecDeque;
use alloc::vec::Vec;
use alloc::string::String;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::sync::SpinLock;
use crate::task::context::TaskContext;
use crate::task::process::{Process, ProcessState, HandleObject, MAX_PROCS};
use crate::mm::heap::{SchdAlloc, SCHD_ALLOC};

extern "C" {
    fn switch_context(old: *mut TaskContext, new: *const TaskContext);
}

// EWMA constants
const SCALE: u32 = 10000;       // 10000 = 100%
const TIMER_INTERVAL: u64 = 1_000_000; // 100ms at 10MHz
const DECAY_1S: u32 = 9048;     // e^(-0.1) ≈ 0.9048 (1-second window)
const DECAY_1M: u32 = 9983;     // e^(-1/600) ≈ 0.9983 (1-minute window)

/// Fixed-point multiply: (a * b) / SCALE
fn mul_scaled(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) / SCALE as u64) as u32
}

/// Fixed-point exponentiation via repeated squaring: base^exp (in SCALE units)
fn pow_scaled(base: u32, mut exp: u32) -> u32 {
    if exp == 0 { return SCALE; }
    let mut result = SCALE;
    let mut b = base;
    while exp > 0 {
        if exp & 1 != 0 { result = mul_scaled(result, b); }
        b = mul_scaled(b, b);
        exp >>= 1;
    }
    result
}

struct Scheduler {
    processes: Vec<Option<Process>, SchdAlloc>,
    ready_queue: VecDeque<usize, SchdAlloc>,
    current: usize, // PID of current process
    initialized: bool,
    last_switch_rdtime: u64, // rdtime when we switched TO the current task
}

impl Scheduler {
    const fn new() -> Self {
        Scheduler {
            processes: Vec::new_in(SCHD_ALLOC),
            ready_queue: VecDeque::new_in(SCHD_ALLOC),
            current: 0,
            initialized: false,
            last_switch_rdtime: 0,
        }
    }

    fn init(&mut self) {
        self.processes = Vec::with_capacity_in(MAX_PROCS, SCHD_ALLOC);
        for _ in 0..MAX_PROCS {
            self.processes.push(None);
        }

        // Create idle process (PID 0) - represents the boot thread
        let idle = Process::new_idle();
        self.processes[0] = Some(idle);
        self.current = 0;
        self.initialized = true;
        self.last_switch_rdtime = crate::task::process::rdtime();
    }
}

static SCHEDULER: SpinLock<Scheduler> = SpinLock::new(Scheduler::new());

/// Stored kernel satp value for restoring after user process trap
static KERNEL_SATP: AtomicUsize = AtomicUsize::new(0);

/// Raw kernel satp value accessible from assembly (trap.S uses this
/// to switch to kernel page table before accessing the kernel stack).
#[no_mangle]
static mut KERNEL_SATP_RAW: usize = 0;

pub fn init() {
    SCHEDULER.lock().init();
    crate::println!("Scheduler initialized (max {} processes)", MAX_PROCS);
}

/// Save the kernel's satp value (call this after enabling paging)
pub fn save_kernel_satp() {
    let satp: usize = crate::read_csr!("satp");
    KERNEL_SATP.store(satp, Ordering::Relaxed);
    unsafe {
        KERNEL_SATP_RAW = satp;
    }
}

/// Spawn a new kernel task. Returns the PID.
#[allow(dead_code)]
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
#[allow(dead_code)]
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

/// Spawn a user-mode process with handle 0 pre-set to boot_ep (boot channel).
#[allow(dead_code)]
pub fn spawn_user_with_boot_channel(user_code: &[u8], name: &str, boot_ep: usize) -> usize {
    let mut sched = SCHEDULER.lock();
    let mut proc = Process::new_user(user_code);
    let pid = proc.pid;
    proc.set_name(name);
    proc.handles[0] = Some(HandleObject::Channel(boot_ep));

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

    crate::println!("  Spawned user [{}] \"{}\" (PID {}, boot_ep={})", pid, name, pid, boot_ep);
    pid
}

/// Spawn a user process from ELF data
#[allow(dead_code)]
pub fn spawn_user_elf(elf_data: &[u8], name: &str) -> usize {
    let mut sched = SCHEDULER.lock();
    let mut proc = Process::new_user_elf(elf_data);
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

    crate::println!("  Spawned user ELF [{}] \"{}\" (PID {})", pid, name, pid);
    pid
}

/// Spawn a user ELF process with handle 0 pre-set to boot_ep (boot channel).
pub fn spawn_user_elf_with_boot_channel(elf_data: &[u8], name: &str, boot_ep: usize) -> usize {
    let mut sched = SCHEDULER.lock();
    let mut proc = Process::new_user_elf(elf_data);
    let pid = proc.pid;
    proc.set_name(name);
    proc.handles[0] = Some(HandleObject::Channel(boot_ep));

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

    crate::println!("  Spawned user ELF [{}] \"{}\" (PID {}, boot_ep={})", pid, name, pid, boot_ep);
    pid
}

/// Spawn a user ELF process with handle 0 = boot_ep and handle 1 = extra_ep.
pub fn spawn_user_elf_with_handles(elf_data: &[u8], name: &str, boot_ep: usize, extra_ep: usize) -> usize {
    let mut sched = SCHEDULER.lock();
    let mut proc = Process::new_user_elf(elf_data);
    let pid = proc.pid;
    proc.set_name(name);
    proc.handles[0] = Some(HandleObject::Channel(boot_ep));
    proc.handles[1] = Some(HandleObject::Channel(extra_ep));

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

    crate::println!("  Spawned user ELF [{}] \"{}\" (PID {}, boot_ep={}, extra_ep={})", pid, name, pid, boot_ep, extra_ep);
    pid
}

/// Look up a handle in the current process's handle table.
pub fn current_process_handle(handle: usize) -> Option<HandleObject> {
    let sched = SCHEDULER.lock();
    let pid = sched.current;
    match sched.processes[pid].as_ref() {
        Some(proc) => proc.lookup_handle(handle),
        None => None,
    }
}

/// Allocate a new handle in the current process for the given HandleObject.
/// Returns the local handle index, or None if the table is full.
pub fn current_process_alloc_handle(obj: HandleObject) -> Option<usize> {
    let mut sched = SCHEDULER.lock();
    let pid = sched.current;
    sched.processes[pid].as_mut().expect("no current process").alloc_handle(obj)
}

/// Free a handle in the current process.
pub fn current_process_free_handle(handle: usize) {
    let mut sched = SCHEDULER.lock();
    let pid = sched.current;
    if let Some(ref mut proc) = sched.processes[pid] {
        proc.free_handle(handle);
    }
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

    // CPU accounting: update old task's EWMA before switching away
    let now = crate::task::process::rdtime();
    let prev_switch = sched.last_switch_rdtime;
    if let Some(ref mut old_proc) = sched.processes[old_pid] {
        let run_time = now.saturating_sub(prev_switch);
        let idle_time = prev_switch.saturating_sub(old_proc.last_switched_away);

        // Phase 1: decay EWMA for idle period (task wasn't running → decays toward 0)
        let idle_ticks = (idle_time / TIMER_INTERVAL) as u32;
        if idle_ticks > 0 {
            let decay_1s = pow_scaled(DECAY_1S, idle_ticks);
            let decay_1m = pow_scaled(DECAY_1M, idle_ticks);
            old_proc.ewma_1s = mul_scaled(old_proc.ewma_1s, decay_1s);
            old_proc.ewma_1m = mul_scaled(old_proc.ewma_1m, decay_1m);
        }

        // Phase 2: update EWMA for running period (task was running → approaches SCALE)
        let run_ticks = (run_time / TIMER_INTERVAL) as u32;
        if run_ticks > 0 {
            let decay_1s = pow_scaled(DECAY_1S, run_ticks);
            let decay_1m = pow_scaled(DECAY_1M, run_ticks);
            old_proc.ewma_1s = SCALE - mul_scaled(SCALE - old_proc.ewma_1s, decay_1s);
            old_proc.ewma_1m = SCALE - mul_scaled(SCALE - old_proc.ewma_1m, decay_1m);
        }

        old_proc.last_switched_away = now;
    }
    sched.last_switch_rdtime = now;

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

    // Disable interrupts BEFORE dropping the lock. This prevents the lock's
    // Drop from re-enabling interrupts (which could allow a timer to fire
    // between lock release and switch_context, causing recursive scheduling).
    // The target task is responsible for re-enabling them:
    // - kernel_task_trampoline does csrsi sstatus,2
    // - user_entry_trampoline transitions to U-mode via sret (SPIE -> SIE)
    crate::arch::csr::disable_interrupts();

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
#[allow(dead_code)]
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

/// Mark current task as dead (called from syscall context, may return).
/// Cleans up all handles (channel + SHM) and SHM-backed mmap regions.
pub fn exit_current_from_syscall() {
    // Collect handles and mmap cleanup info while holding the lock,
    // then release the lock BEFORE calling channel_close (which may call
    // wake_process, requiring the SCHEDULER lock — would deadlock otherwise).
    let mut channel_eps: [usize; crate::task::process::MAX_HANDLES] = [usize::MAX; crate::task::process::MAX_HANDLES];
    let mut shm_ids: [usize; crate::task::process::MAX_HANDLES] = [usize::MAX; crate::task::process::MAX_HANDLES];
    let mut notify_ep = 0usize;
    {
        let mut sched = SCHEDULER.lock();
        let pid = sched.current;
        if let Some(ref mut proc) = sched.processes[pid] {
            // Snapshot exit_notify_ep before cleanup
            notify_ep = proc.exit_notify_ep;
            proc.exit_notify_ep = 0;
            // Snapshot handles and clear them from the process
            for i in 0..crate::task::process::MAX_HANDLES {
                if let Some(handle_obj) = proc.handles[i].take() {
                    match handle_obj {
                        HandleObject::Channel(ep) => {
                            channel_eps[i] = ep;
                        }
                        HandleObject::Shm { id, .. } => {
                            shm_ids[i] = id;
                        }
                    }
                }
            }
            // Clean up mmap regions while holding the lock (no lock contention here)
            if proc.user_satp != 0 {
                let root_ppn = crate::mm::address::PhysPageNum(proc.user_satp & ((1usize << 44) - 1));
                let mut pt = crate::mm::page_table::PageTable::from_root(root_ppn);
                for slot in proc.mmap_regions.iter_mut() {
                    if let Some(region) = slot.take() {
                        for j in 0..region.page_count {
                            let vpn = crate::mm::address::VirtPageNum(region.base_ppn + j);
                            pt.unmap(vpn);
                            if region.shm_id.is_none() {
                                // Anonymous: free the frame
                                crate::mm::frame::frame_dealloc(
                                    crate::mm::address::PhysPageNum(region.base_ppn + j),
                                );
                            }
                            // SHM-backed: do NOT free the frame
                        }
                    }
                }
            }
            proc.state = ProcessState::Dead;
        }
    }
    // SCHEDULER lock released — now safe to call channel_close (which may wake_process)

    // Send exit notification before closing handles (so the receiver wakes up)
    if notify_ep != 0 {
        let mut msg = crate::ipc::Message::new();
        msg.data[0] = 0; // exit code (always 0 for now)
        msg.len = 1;
        if let Ok(wake) = crate::ipc::channel_send(notify_ep, msg) {
            if wake != 0 {
                crate::task::wake_process(wake);
            }
        }
        crate::ipc::channel_close(notify_ep);
    }

    for i in 0..crate::task::process::MAX_HANDLES {
        if channel_eps[i] != usize::MAX {
            crate::ipc::channel_close(channel_eps[i]);
        }
        if shm_ids[i] != usize::MAX {
            crate::ipc::shm_dec_ref(shm_ids[i]);
        }
    }
    schedule();
}

/// Set the exit notification endpoint for a process.
/// When the process exits, the kernel will send the exit code on this endpoint.
pub fn set_exit_notify_ep(pid: usize, ep: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        proc.exit_notify_ep = ep;
    }
}

/// Set a process to Blocked state
pub fn block_process(pid: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        // Check wakeup_pending: if a wake arrived between our poll and this
        // block call, consume the pending wakeup and stay Ready (don't block).
        if proc.wakeup_pending {
            proc.wakeup_pending = false;
            return;
        }
        proc.state = ProcessState::Blocked;
    }
}

/// Wake a blocked process (set to Ready and add to FRONT of ready queue).
/// Pushing to front gives woken receivers priority, enabling fast IPC round-trips.
/// If the process is Running or Ready, set wakeup_pending so a subsequent
/// block_process() call won't actually block.
pub fn wake_process(pid: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        if proc.state == ProcessState::Blocked {
            proc.state = ProcessState::Ready;
            sched.ready_queue.push_front(pid);
        } else if proc.state == ProcessState::Running || proc.state == ProcessState::Ready {
            proc.wakeup_pending = true;
        }
    }
}

/// Compute effective EWMA for a process without writing back.
/// For idle processes: just decay from last_switched_away.
/// For the currently running process: idle decay + running update.
fn effective_ewma(proc: &Process, now: u64, is_current: bool, last_switch_rdtime: u64) -> (u32, u32) {
    let mut e1s = proc.ewma_1s;
    let mut e1m = proc.ewma_1m;

    if is_current {
        // Currently running: idle time was before last_switch, run time is since then
        let idle_time = last_switch_rdtime.saturating_sub(proc.last_switched_away);
        let idle_ticks = (idle_time / TIMER_INTERVAL) as u32;
        if idle_ticks > 0 {
            e1s = mul_scaled(e1s, pow_scaled(DECAY_1S, idle_ticks));
            e1m = mul_scaled(e1m, pow_scaled(DECAY_1M, idle_ticks));
        }
        let run_time = now.saturating_sub(last_switch_rdtime);
        let run_ticks = (run_time / TIMER_INTERVAL) as u32;
        if run_ticks > 0 {
            e1s = SCALE - mul_scaled(SCALE - e1s, pow_scaled(DECAY_1S, run_ticks));
            e1m = SCALE - mul_scaled(SCALE - e1m, pow_scaled(DECAY_1M, run_ticks));
        }
    } else {
        // Not running: just decay since last switched away
        let idle_time = now.saturating_sub(proc.last_switched_away);
        let idle_ticks = (idle_time / TIMER_INTERVAL) as u32;
        if idle_ticks > 0 {
            e1s = mul_scaled(e1s, pow_scaled(DECAY_1S, idle_ticks));
            e1m = mul_scaled(e1m, pow_scaled(DECAY_1M, idle_ticks));
        }
    }
    (e1s, e1m)
}

/// Return a formatted string listing all processes
pub fn process_list() -> String {
    crate::trace::trace_kernel(b"process_list-enter");
    let sched = SCHEDULER.lock();
    let now = crate::task::process::rdtime();
    let current_pid = sched.current;
    let last_switch = sched.last_switch_rdtime;

    let mut out = String::new();
    let _ = writeln!(out, "  PID  STATE     CPU1s  CPU1m  MEM     NAME");
    let _ = writeln!(out, "  ---  --------  -----  -----  ------  ----------------");
    for (i, slot) in sched.processes.iter().enumerate() {
        if let Some(proc) = slot {
            let state = match proc.state {
                ProcessState::Ready => "Ready   ",
                ProcessState::Running => "Running ",
                ProcessState::Blocked => "Blocked ",
                ProcessState::Dead => "Dead    ",
            };
            let (e1s, e1m) = effective_ewma(proc, now, i == current_pid, last_switch);
            let mem_kb = proc.mem_pages as usize * 4; // 4 KiB per page
            let _ = writeln!(out, "  {:3}  {}  {:2}.{:<1}%  {:2}.{:<1}%  {:>4}K  {}",
                i, state,
                e1s / 100, (e1s / 10) % 10,
                e1m / 100, (e1m / 10) % 10,
                mem_kb,
                proc.name());
        }
    }
    drop(sched);
    crate::trace::trace_kernel(b"process_list-exit");
    out
}

/// Return a formatted string listing per-process memory usage.
pub fn process_mem_list() -> String {
    let sched = SCHEDULER.lock();
    let mut out = String::new();
    let _ = writeln!(out, "  PID  NAME              MEM");
    let _ = writeln!(out, "  ---  ----------------  ------");
    for (i, slot) in sched.processes.iter().enumerate() {
        if let Some(proc) = slot {
            if proc.state == ProcessState::Dead { continue; }
            let mem_kb = proc.mem_pages as usize * 4;
            let _ = writeln!(out, "  {:3}  {:<16}  {:>4}K", i, proc.name(), mem_kb);
        }
    }
    out
}

/// Adjust mem_pages for the current process by `delta` pages.
pub fn current_process_adjust_mem_pages(delta: i32) {
    let mut sched = SCHEDULER.lock();
    let pid = sched.current;
    if let Some(ref mut proc) = sched.processes[pid] {
        proc.mem_pages = (proc.mem_pages as i32 + delta) as u32;
    }
}

/// Count alive (non-Dead) processes
#[allow(dead_code)]
pub fn alive_count() -> usize {
    let sched = SCHEDULER.lock();
    sched.processes.iter().filter(|slot| {
        matches!(slot, Some(p) if p.state != ProcessState::Dead)
    }).count()
}

/// Check if a specific PID is alive
#[allow(dead_code)]
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
        (*out).sepc = proc.user_entry;
        (*out).user_sp = proc.user_stack_top;
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

/// Get current process's user_satp value (for mmap/munmap).
pub fn current_process_user_satp() -> usize {
    let sched = SCHEDULER.lock();
    let pid = sched.current;
    match sched.processes[pid].as_ref() {
        Some(proc) => proc.user_satp,
        None => 0,
    }
}

/// Add an mmap region to the current process. Returns true on success.
pub fn current_process_add_mmap(base_ppn: usize, page_count: usize, shm_id: Option<usize>) -> bool {
    let mut sched = SCHEDULER.lock();
    let pid = sched.current;
    if let Some(ref mut proc) = sched.processes[pid] {
        proc.add_mmap_region(base_ppn, page_count, shm_id)
    } else {
        false
    }
}

/// Remove an mmap region from the current process.
/// Returns Some(shm_id) if found (None inside means anonymous, Some(id) means SHM).
/// Returns None if not found.
pub fn current_process_remove_mmap(base_ppn: usize, page_count: usize) -> Option<Option<usize>> {
    let mut sched = SCHEDULER.lock();
    let pid = sched.current;
    if let Some(ref mut proc) = sched.processes[pid] {
        proc.remove_mmap_region(base_ppn, page_count)
    } else {
        None
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
