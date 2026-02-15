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
    global_cpu_ticks: u64, // total non-idle CPU ticks across all processes
}

impl Scheduler {
    const fn new() -> Self {
        Scheduler {
            processes: Vec::new_in(SCHD_ALLOC),
            ready_queue: VecDeque::new_in(SCHD_ALLOC),
            current: 0,
            initialized: false,
            last_switch_rdtime: 0,
            global_cpu_ticks: 0,
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

/// Dedicated trap stack for kernel-mode traps. When a trap occurs from
/// S-mode, _from_kernel switches sp to this stack before saving the trap
/// frame. This ensures the trap handler always has a known-good stack,
/// even during kernel stack overflow. 8 KiB is ample for trap handling.
const TRAP_STACK_SIZE: usize = 8192;
#[no_mangle]
static mut KERNEL_TRAP_STACK: [u8; TRAP_STACK_SIZE] = [0; TRAP_STACK_SIZE];
/// Points to the top of KERNEL_TRAP_STACK. Initialized in init().
#[no_mangle]
static mut KERNEL_TRAP_STACK_TOP: usize = 0;

pub fn init() {
    SCHEDULER.lock().init();
    unsafe {
        KERNEL_TRAP_STACK_TOP =
            core::ptr::addr_of!(KERNEL_TRAP_STACK) as usize + TRAP_STACK_SIZE;
    }
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

/// Find a free process slot: prefer Dead slots for reuse, then None slots.
/// Returns the PID (slot index). Panics if no slots available.
/// When reusing a Dead slot, frees the old process's kernel stack (which
/// could not be freed during exit because the dying process was still on it).
fn find_free_slot(sched: &mut Scheduler) -> usize {
    // First pass: look for Dead slots to reuse (skip idle at 0)
    for i in 1..sched.processes.len() {
        if let Some(ref p) = sched.processes[i] {
            if p.state == ProcessState::Dead {
                // Free old kernel stack before reusing the slot (includes guard page)
                let kstack_base = p.kernel_stack_base;
                if kstack_base != 0 {
                    let guard_addr = kstack_base - super::process::KERNEL_GUARD_PAGES * crate::mm::address::PAGE_SIZE;
                    // Restore the guard page's PTE before freeing — otherwise the
                    // page has an empty PTE and will fault when reallocated.
                    super::process::restore_guard_page(guard_addr);
                    let alloc_ppn = guard_addr / crate::mm::address::PAGE_SIZE;
                    for j in 0..super::process::KERNEL_STACK_ALLOC_PAGES {
                        crate::mm::frame::frame_dealloc(
                            crate::mm::address::PhysPageNum(alloc_ppn + j),
                        );
                    }
                }
                sched.processes[i] = None;
                return i;
            }
        }
    }
    // Second pass: look for None slots
    for i in 1..sched.processes.len() {
        if sched.processes[i].is_none() {
            return i;
        }
    }
    panic!("No free process slots (max {})", MAX_PROCS);
}

/// Spawn a new kernel task. Returns the PID.
#[allow(dead_code)]
pub fn spawn(entry: fn()) -> usize {
    let mut sched = SCHEDULER.lock();
    let pid = find_free_slot(&mut sched);
    let proc = Process::new_kernel(entry);

    sched.processes[pid] = Some(proc);
    sched.ready_queue.push_back(pid);

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
    let pid = find_free_slot(&mut sched);
    let mut proc = Process::new_user(user_code);
    proc.set_name(name);

    sched.processes[pid] = Some(proc);
    sched.ready_queue.push_back(pid);

    crate::println!("  Spawned user [{}] \"{}\" (PID {})", pid, name, pid);
    pid
}

/// Spawn a user-mode process with handle 0 pre-set to boot_ep (boot channel).
#[allow(dead_code)]
pub fn spawn_user_with_boot_channel(user_code: &[u8], name: &str, boot_ep: usize) -> usize {
    let mut sched = SCHEDULER.lock();
    let pid = find_free_slot(&mut sched);
    let mut proc = Process::new_user(user_code);
    proc.set_name(name);
    proc.handles[0] = Some(HandleObject::Channel(boot_ep));

    sched.processes[pid] = Some(proc);
    sched.ready_queue.push_back(pid);

    crate::println!("  Spawned user [{}] \"{}\" (PID {}, boot_ep={})", pid, name, pid, boot_ep);
    pid
}

/// Spawn a user process from ELF data
#[allow(dead_code)]
pub fn spawn_user_elf(elf_data: &[u8], name: &str) -> usize {
    let mut sched = SCHEDULER.lock();
    let pid = find_free_slot(&mut sched);
    let mut proc = Process::new_user_elf(elf_data);
    proc.set_name(name);

    sched.processes[pid] = Some(proc);
    sched.ready_queue.push_back(pid);

    crate::println!("  Spawned user ELF [{}] \"{}\" (PID {})", pid, name, pid);
    pid
}

/// Spawn a user ELF process with handle 0 pre-set to boot_ep (boot channel).
pub fn spawn_user_elf_with_boot_channel(elf_data: &[u8], name: &str, boot_ep: usize) -> usize {
    let mut sched = SCHEDULER.lock();
    let pid = find_free_slot(&mut sched);
    let mut proc = Process::new_user_elf(elf_data);
    proc.set_name(name);
    proc.handles[0] = Some(HandleObject::Channel(boot_ep));

    sched.processes[pid] = Some(proc);
    sched.ready_queue.push_back(pid);

    crate::println!("  Spawned user ELF [{}] \"{}\" (PID {}, boot_ep={})", pid, name, pid, boot_ep);
    pid
}

/// Spawn a user ELF process with handle 0 = boot_ep and handle 1 = extra_ep.
pub fn spawn_user_elf_with_handles(elf_data: &[u8], name: &str, boot_ep: usize, extra_ep: usize) -> usize {
    let mut sched = SCHEDULER.lock();
    let pid = find_free_slot(&mut sched);
    let mut proc = Process::new_user_elf(elf_data);
    proc.set_name(name);
    proc.handles[0] = Some(HandleObject::Channel(boot_ep));
    proc.handles[1] = Some(HandleObject::Channel(extra_ep));

    sched.processes[pid] = Some(proc);
    sched.ready_queue.push_back(pid);

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

/// Non-blocking version of current_pid for use in fault handlers
/// where the SCHEDULER lock may already be held.
pub fn try_current_pid() -> Option<usize> {
    SCHEDULER.try_lock().map(|s| s.current)
}

/// Return (wall_ticks, global_cpu_ticks) for the SYS_CLOCK syscall.
/// global_cpu_ticks = total non-idle CPU time across all processes.
pub fn global_clock() -> (u64, u64) {
    let sched = SCHEDULER.lock();
    let now = crate::task::process::rdtime();
    let current_slice = if sched.current != 0 {
        now.saturating_sub(sched.last_switch_rdtime)
    } else {
        0
    };
    (now, sched.global_cpu_ticks + current_slice)
}

/// Yield the current task and schedule the next one.
///
/// Idle (PID 0) is NEVER placed in the ready queue.  It is the fallback
/// task: when the queue is empty and the current task cannot continue
/// (Blocked or Dead), we switch directly to idle.  This prevents idle
/// from stealing timeslices when real work is available.
pub fn schedule() {
    let mut sched = SCHEDULER.lock();
    if !sched.initialized {
        return;
    }

    let old_pid = sched.current;

    // Pick next task from ready queue, or fall back to idle (PID 0).
    let next_pid = match sched.ready_queue.pop_front() {
        Some(pid) => pid,
        None => {
            // Queue is empty.  If the current task is still Running
            // (timer preemption or yield with nothing else to run), let
            // it keep running.  Otherwise (Blocked/Dead) fall back to idle.
            let still_running = sched.processes[old_pid]
                .as_ref()
                .is_some_and(|p| p.state == ProcessState::Running);
            if still_running {
                return;
            }
            0 // fall back to idle
        }
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

        // Accumulate global CPU time (exclude idle task, PID 0)
        if old_pid != 0 {
            sched.global_cpu_ticks += run_time;
        }
    }
    sched.last_switch_rdtime = now;

    // Put old task back in ready queue if still Running.
    // NEVER put idle (PID 0) in the ready queue — it is the fallback task.
    if old_pid != 0 {
        if let Some(ref mut old_proc) = sched.processes[old_pid] {
            if old_proc.state == ProcessState::Running {
                old_proc.state = ProcessState::Ready;
                sched.ready_queue.push_back(old_pid);
            }
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

/// Terminate the current process: clean up all resources (handles, mmap regions,
/// physical frames), send exit notification to init, mark Dead, and schedule away.
/// Used by both the exit syscall and the fault handler for U-mode faults.
/// Never returns (schedule() switches away from the Dead process permanently).
pub fn terminate_current_process() {
    use crate::mm::address::{PhysPageNum, VirtPageNum, PAGE_SIZE};
    use crate::mm::heap::PGTB_ALLOC;

    // Collect handles and cleanup info while holding the lock,
    // then release the lock BEFORE calling channel_close (which may call
    // wake_process, requiring the SCHEDULER lock — would deadlock otherwise).
    let mut channel_eps: [usize; crate::task::process::MAX_HANDLES] = [usize::MAX; crate::task::process::MAX_HANDLES];
    let mut shm_ids: [usize; crate::task::process::MAX_HANDLES] = [usize::MAX; crate::task::process::MAX_HANDLES];
    let mut notify_ep = 0usize;

    // Frame cleanup info
    let mut pt_frames: alloc::vec::Vec<PhysPageNum, crate::mm::heap::PgtbAlloc> = alloc::vec::Vec::new_in(PGTB_ALLOC);
    let mut code_ppn: usize = 0;
    let mut code_pages: usize = 0;
    let mut ustack_ppn: usize = 0;
    let mut ustack_pages: usize = 0;
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
            // Clean up mmap regions (unmap and free anonymous frames)
            if proc.user_satp != 0 {
                let root_ppn = PhysPageNum(proc.user_satp & ((1usize << 44) - 1));
                let mut pt = crate::mm::page_table::PageTable::from_root(root_ppn);
                for slot in proc.mmap_regions.iter_mut() {
                    if let Some(region) = slot.take() {
                        for j in 0..region.page_count {
                            let vpn = VirtPageNum(region.base_ppn + j);
                            pt.unmap(vpn);
                            if region.shm_id.is_none() {
                                crate::mm::frame::frame_dealloc(
                                    PhysPageNum(region.base_ppn + j),
                                );
                            }
                        }
                    }
                }
            }

            // Snapshot frame cleanup info
            pt_frames = core::mem::replace(&mut proc.pt_frames, alloc::vec::Vec::new_in(PGTB_ALLOC));
            code_ppn = proc.code_ppn;
            code_pages = proc.code_pages;
            if proc.is_user && proc.user_stack_top != 0 {
                ustack_pages = 8; // USER_STACK_PAGES
                ustack_ppn = (proc.user_stack_top / PAGE_SIZE) - ustack_pages;
            }

            proc.state = ProcessState::Dead;
        }
    }
    // SCHEDULER lock released — now safe to call channel_close (which may wake_process)

    // Send exit notification before closing handles (so the receiver wakes up)
    if notify_ep != 0 {
        let mut msg = crate::ipc::Message::new();
        let notif = rvos_proto::process::ExitNotification { exit_code: 0 };
        msg.len = rvos_wire::to_bytes(&notif, &mut msg.data).unwrap_or(0);
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

    // Free physical frames (code, user stack, page table nodes).
    // NOTE: Do NOT free kernel stack here — we're still executing on it!
    // Kernel stack is freed when the Dead slot is reused by a new process.
    if code_pages > 0 {
        for i in 0..code_pages {
            crate::mm::frame::frame_dealloc(PhysPageNum(code_ppn + i));
        }
    }
    if ustack_pages > 0 {
        for i in 0..ustack_pages {
            crate::mm::frame::frame_dealloc(PhysPageNum(ustack_ppn + i));
        }
    }
    // Free page table node frames last (mmap unmap above needed the page table)
    for &frame in &pt_frames {
        crate::mm::frame::frame_dealloc(frame);
    }
    // Explicitly drop the Vec before schedule() — schedule() never returns for
    // Dead processes (switch_context saves context that will never be restored),
    // so local variables with heap allocations would leak their backing storage.
    drop(pt_frames);

    schedule();
}

/// Convenience alias: terminate from syscall context (SYS_EXIT).
pub fn exit_current_from_syscall() {
    terminate_current_process();
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

/// Read mem_pages for the current process.
pub fn current_process_mem_pages() -> u32 {
    let sched = SCHEDULER.lock();
    let pid = sched.current;
    match sched.processes[pid].as_ref() {
        Some(proc) => proc.mem_pages,
        None => 0,
    }
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
