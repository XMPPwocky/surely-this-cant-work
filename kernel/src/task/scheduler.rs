use alloc::collections::VecDeque;
use alloc::vec::Vec;
use alloc::string::String;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::sync::SpinLock;
use crate::arch::trap::TrapFrame;
use crate::task::context::TaskContext;
use crate::task::process::{Process, ProcessState, HandleObject, HandleInfo, MAX_PROCS};
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
    let mut sched = SCHEDULER.lock();
    sched.init();
    unsafe {
        KERNEL_TRAP_STACK_TOP =
            core::ptr::addr_of!(KERNEL_TRAP_STACK) as usize + TRAP_STACK_SIZE;
    }
    // Set sscratch to the idle task's TrapContext so that any trap
    // before the first schedule() saves to the right place.
    let trap_ctx_ptr = &sched.processes[0].as_ref().unwrap().trap_ctx
        as *const crate::task::context::TrapContext as usize;
    drop(sched);
    unsafe {
        core::arch::asm!("csrw sscratch, {}", in(reg) trap_ctx_ptr);
    }
    crate::println!("Scheduler initialized (max {} processes, sscratch={:#x})", MAX_PROCS, trap_ctx_ptr);
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
/// Returns the PID (slot index), or None if no slots available.
/// When reusing a Dead slot, frees the old process's kernel stack (which
/// could not be freed during exit because the dying process was still on it).
fn find_free_slot(sched: &mut Scheduler) -> Option<usize> {
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
                return Some(i);
            }
        }
    }
    // Second pass: look for None slots
    (1..sched.processes.len()).find(|&i| sched.processes[i].is_none())
}

/// After inserting a Process into its slot, set context.s1 to point to the
/// task's TrapContext.  The trampolines (kernel_task_trampoline and
/// user_entry_trampoline) use s1 to set sscratch on first run.
fn fixup_trap_ctx_ptr(sched: &mut Scheduler, pid: usize) {
    let proc = sched.processes[pid].as_mut().unwrap();
    let ptr = &proc.trap_ctx as *const crate::task::context::TrapContext as usize;
    proc.context.s1 = ptr;
}

/// Spawn a new kernel task. Returns the PID, or None if no slots or allocation failed.
#[allow(dead_code)]
pub fn spawn(entry: fn()) -> Option<usize> {
    let mut sched = SCHEDULER.lock();
    let pid = find_free_slot(&mut sched)?;
    let proc = match Process::new_kernel(entry) {
        Ok(p) => p,
        Err(e) => {
            crate::println!("[spawn] kernel task failed: {}", e);
            return None;
        }
    };

    sched.processes[pid] = Some(proc);
    fixup_trap_ctx_ptr(&mut sched, pid);
    sched.ready_queue.push_back(pid);

    Some(pid)
}

/// Spawn with a name for display purposes
pub fn spawn_named(entry: fn(), name: &str) -> Option<usize> {
    let pid = spawn(entry)?;
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes[pid] {
        proc.set_name(name);
    }
    crate::println!("  Spawned [{}] \"{}\" (PID {})", pid, name, pid);
    Some(pid)
}

/// Spawn a user-mode process from machine code bytes. Returns the PID.
#[allow(dead_code)]
pub fn spawn_user(user_code: &[u8], name: &str) -> Option<usize> {
    let mut sched = SCHEDULER.lock();
    let pid = find_free_slot(&mut sched)?;
    let mut proc = match Process::new_user(user_code) {
        Ok(p) => p,
        Err(e) => {
            crate::println!("[spawn] user process '{}' failed: {}", name, e);
            return None;
        }
    };
    proc.set_name(name);

    sched.processes[pid] = Some(proc);
    fixup_trap_ctx_ptr(&mut sched, pid);
    sched.ready_queue.push_back(pid);

    crate::println!("  Spawned user [{}] \"{}\" (PID {})", pid, name, pid);
    Some(pid)
}

/// Spawn a user-mode process with handle 0 pre-set to boot_ep (boot channel).
#[allow(dead_code)]
pub fn spawn_user_with_boot_channel(user_code: &[u8], name: &str, boot_ep: crate::ipc::OwnedEndpoint) -> Option<usize> {
    let mut sched = SCHEDULER.lock();
    let pid = find_free_slot(&mut sched)?;
    let mut proc = match Process::new_user(user_code) {
        Ok(p) => p,
        Err(e) => {
            crate::println!("[spawn] user process '{}' failed: {}", name, e);
            return None;
        }
    };
    proc.set_name(name);
    let ep_raw = boot_ep.raw();
    proc.handles[0] = Some(HandleObject::Channel(boot_ep));

    sched.processes[pid] = Some(proc);
    fixup_trap_ctx_ptr(&mut sched, pid);
    sched.ready_queue.push_back(pid);

    crate::println!("  Spawned user [{}] \"{}\" (PID {}, boot_ep={})", pid, name, pid, ep_raw);
    Some(pid)
}

/// Spawn a user process from ELF data
#[allow(dead_code)]
pub fn spawn_user_elf(elf_data: &[u8], name: &str) -> Option<usize> {
    let mut sched = SCHEDULER.lock();
    let pid = find_free_slot(&mut sched)?;
    let mut proc = match Process::new_user_elf(elf_data) {
        Ok(p) => p,
        Err(e) => {
            crate::println!("[spawn] user ELF '{}' failed: {}", name, e);
            return None;
        }
    };
    proc.set_name(name);

    sched.processes[pid] = Some(proc);
    fixup_trap_ctx_ptr(&mut sched, pid);
    sched.ready_queue.push_back(pid);

    crate::println!("  Spawned user ELF [{}] \"{}\" (PID {})", pid, name, pid);
    Some(pid)
}

/// Spawn a user ELF process with handle 0 pre-set to boot_ep (boot channel).
pub fn spawn_user_elf_with_boot_channel(elf_data: &[u8], name: &str, boot_ep: crate::ipc::OwnedEndpoint) -> Option<usize> {
    let mut sched = SCHEDULER.lock();
    let pid = find_free_slot(&mut sched)?;
    let mut proc = match Process::new_user_elf(elf_data) {
        Ok(p) => p,
        Err(e) => {
            crate::println!("[spawn] user ELF '{}' failed: {}", name, e);
            return None;
        }
    };
    proc.set_name(name);
    let ep_raw = boot_ep.raw();
    proc.handles[0] = Some(HandleObject::Channel(boot_ep));

    sched.processes[pid] = Some(proc);
    fixup_trap_ctx_ptr(&mut sched, pid);
    sched.ready_queue.push_back(pid);

    crate::println!("  Spawned user ELF [{}] \"{}\" (PID {}, boot_ep={})", pid, name, pid, ep_raw);
    Some(pid)
}

/// Spawn a user ELF process with handle 0 = boot_ep and handle 1 = extra_ep.
pub fn spawn_user_elf_with_handles(elf_data: &[u8], name: &str, boot_ep: crate::ipc::OwnedEndpoint, extra_ep: crate::ipc::OwnedEndpoint) -> Option<usize> {
    let mut sched = SCHEDULER.lock();
    let pid = find_free_slot(&mut sched)?;
    let mut proc = match Process::new_user_elf(elf_data) {
        Ok(p) => p,
        Err(e) => {
            crate::println!("[spawn] user ELF '{}' failed: {}", name, e);
            return None;
        }
    };
    proc.set_name(name);
    let boot_raw = boot_ep.raw();
    let extra_raw = extra_ep.raw();
    proc.handles[0] = Some(HandleObject::Channel(boot_ep));
    proc.handles[1] = Some(HandleObject::Channel(extra_ep));

    sched.processes[pid] = Some(proc);
    fixup_trap_ctx_ptr(&mut sched, pid);
    sched.ready_queue.push_back(pid);

    crate::println!("  Spawned user ELF [{}] \"{}\" (PID {}, boot_ep={}, extra_ep={})", pid, name, pid, boot_raw, extra_raw);
    Some(pid)
}

/// Look up a handle in the current process's handle table.
/// Returns lightweight HandleInfo (Copy, no ownership) for reading.
pub fn current_process_handle(handle: usize) -> Option<HandleInfo> {
    let sched = SCHEDULER.lock();
    let pid = sched.current;
    match sched.processes[pid].as_ref() {
        Some(proc) => proc.lookup_handle(handle),
        None => None,
    }
}

/// Allocate a new handle in the current process for the given HandleObject.
/// Returns the local handle index, or None if the table is full.
/// On failure, the HandleObject is dropped (auto-closing the resource).
pub fn current_process_alloc_handle(obj: HandleObject) -> Option<usize> {
    let mut sched = SCHEDULER.lock();
    let pid = sched.current;
    sched.processes[pid].as_mut().expect("no current process").alloc_handle(obj)
}

/// Take a handle from the current process, returning the HandleObject.
/// The caller owns the returned object. Dropping it auto-closes the resource.
///
/// IMPORTANT: The SCHEDULER lock is released before this function returns,
/// so the caller can safely drop the returned HandleObject (which may call
/// channel_close → wake_process → SCHEDULER lock).
pub fn current_process_take_handle(handle: usize) -> Option<HandleObject> {
    let mut sched = SCHEDULER.lock();
    let pid = sched.current;
    match sched.processes[pid].as_mut() {
        Some(proc) => proc.take_handle(handle),
        None => None,
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
    // Capture interrupt state BEFORE acquiring the lock.  The SpinLock
    // disables SIE internally, so reading SIE after lock() always sees 0.
    let interrupts_were_on = crate::arch::csr::interrupts_enabled();

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

    crate::kstat::inc(&crate::kstat::SCHED_SWITCHES);

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

    // Compute TrapContext pointers for sscratch management.
    // sscratch must ALWAYS point to the running task's TrapContext so that
    // _trap_entry saves registers to the correct location.
    let new_trap_ctx = &sched.processes[next_pid].as_ref().unwrap().trap_ctx
        as *const crate::task::context::TrapContext as usize;
    let old_trap_ctx = &sched.processes[old_pid].as_ref().unwrap().trap_ctx
        as *const crate::task::context::TrapContext as usize;

    // Suppress interrupt restore: sched.current has already been set to
    // next_pid, but we haven't switched yet.  If drop() re-enabled
    // interrupts and a timer fired, preempt() would read the wrong current
    // PID and corrupt next_pid's TaskContext.  By suppressing the restore,
    // interrupts stay disabled through switch_context.
    sched.suppress_irq_restore();
    drop(sched);

    unsafe {
        // Set sscratch to the NEW task's TrapContext before switching.
        // The new task may re-enable interrupts and take a trap — sscratch
        // must point to its TrapContext so _trap_entry saves correctly.
        core::arch::asm!("csrw sscratch, {}", in(reg) new_trap_ctx);
        switch_context(old_ctx, new_ctx);
        // Resumed: restore sscratch for ourselves before re-enabling
        // interrupts. (Interrupts are still disabled here, so this is safe.)
        core::arch::asm!("csrw sscratch, {}", in(reg) old_trap_ctx);
    }

    // After switch_context returns, we've been switched BACK to this task.
    // Only re-enable interrupts if they were on before (i.e., we were NOT
    // called from inside a trap handler).
    if interrupts_were_on {
        crate::arch::csr::enable_interrupts();
    }
}

/// Preemptive context switch. Called from trap_handler() when NEED_RESCHED
/// is set (timer tick).
///
/// Uses switch_context (just like schedule()) so that the new task resumes
/// correctly regardless of how it was last suspended — whether by cooperative
/// yield (schedule) or preemption.  When switch_context returns (the old
/// task has been resumed), we return old_tf so the asm epilogue restores
/// from it and srets back to the interrupted code.
///
/// The handler stack for S-mode traps is the task's own kernel stack (not
/// a shared trap stack), so the call frames survive across switch_context.
pub fn preempt(old_tf: &mut TrapFrame) -> *mut TrapFrame {
    let mut sched = SCHEDULER.lock();
    if !sched.initialized {
        return old_tf as *mut TrapFrame;
    }

    let old_pid = sched.current;

    // Pick next task from ready queue
    let next_pid = match sched.ready_queue.pop_front() {
        Some(pid) => pid,
        None => {
            // Nothing else to run — stay on current task
            return old_tf as *mut TrapFrame;
        }
    };

    if next_pid == old_pid {
        sched.ready_queue.push_back(next_pid);
        return old_tf as *mut TrapFrame;
    }

    crate::kstat::inc(&crate::kstat::SCHED_PREEMPTS);

    // CPU accounting (same as schedule)
    let now = crate::task::process::rdtime();
    let prev_switch = sched.last_switch_rdtime;
    if let Some(ref mut old_proc) = sched.processes[old_pid] {
        let run_time = now.saturating_sub(prev_switch);
        let idle_time = prev_switch.saturating_sub(old_proc.last_switched_away);

        let idle_ticks = (idle_time / TIMER_INTERVAL) as u32;
        if idle_ticks > 0 {
            let decay_1s = pow_scaled(DECAY_1S, idle_ticks);
            let decay_1m = pow_scaled(DECAY_1M, idle_ticks);
            old_proc.ewma_1s = mul_scaled(old_proc.ewma_1s, decay_1s);
            old_proc.ewma_1m = mul_scaled(old_proc.ewma_1m, decay_1m);
        }

        let run_ticks = (run_time / TIMER_INTERVAL) as u32;
        if run_ticks > 0 {
            let decay_1s = pow_scaled(DECAY_1S, run_ticks);
            let decay_1m = pow_scaled(DECAY_1M, run_ticks);
            old_proc.ewma_1s = SCALE - mul_scaled(SCALE - old_proc.ewma_1s, decay_1s);
            old_proc.ewma_1m = SCALE - mul_scaled(SCALE - old_proc.ewma_1m, decay_1m);
        }

        old_proc.last_switched_away = now;

        if old_pid != 0 {
            sched.global_cpu_ticks += run_time;
        }
    }
    sched.last_switch_rdtime = now;

    // Put old task back in ready queue if still Running
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

    // Set sscratch for the new task (same invariant as schedule()).
    let new_trap_ctx = &sched.processes[next_pid].as_ref().unwrap().trap_ctx
        as *const crate::task::context::TrapContext as usize;

    // Drop the lock BEFORE switching (critical!)
    // Don't re-enable interrupts: we're inside the trap handler (SIE=0),
    // and the eventual sret will restore SIE from SPIE.
    drop(sched);

    unsafe {
        core::arch::asm!("csrw sscratch, {}", in(reg) new_trap_ctx);
        switch_context(old_ctx, new_ctx);
        // No need to restore sscratch here: SIE=0 (in trap handler), and
        // the asm epilogue (csrw sscratch, t0) will set it from old_tf.
    }

    // switch_context returned — we've been resumed.  Return old_tf so the
    // asm epilogue (after trap_handler returns) restores from it and srets.
    old_tf as *mut TrapFrame
}

/// Safe return handler for kernel tasks. When a kernel task's entry
/// function returns (instead of looping forever), sret set ra to this
/// function.  Without it, ra=0 and the task jumps to address 0.
#[no_mangle]
extern "C" fn kernel_task_return_handler() -> ! {
    exit_current()
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

    // Take handles and cleanup info while holding the lock,
    // then release the lock BEFORE dropping handles (which may call
    // channel_close → wake_process, requiring the SCHEDULER lock).
    let mut taken_handles: [Option<HandleObject>; crate::task::process::MAX_HANDLES] =
        [const { None }; crate::task::process::MAX_HANDLES];
    let mut notify_ep_raw = 0usize;
    let mut debug_event_ep_raw = 0usize;

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
            notify_ep_raw = proc.exit_notify_ep;
            proc.exit_notify_ep = 0;
            // Take handles from the process (RAII ownership transfer)
            for (i, slot) in taken_handles.iter_mut().enumerate().take(crate::task::process::MAX_HANDLES) {
                *slot = proc.take_handle(i);
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
                let stack_top_ppn = proc.user_stack_top / PAGE_SIZE;
                ustack_ppn = match stack_top_ppn.checked_sub(ustack_pages) {
                    Some(ppn) => ppn,
                    None => { ustack_pages = 0; 0 } // skip cleanup if invalid
                };
            }

            // Snapshot debug state for cleanup after lock release
            if proc.debug_attached {
                debug_event_ep_raw = proc.debug_event_ep;
                proc.debug_attached = false;
                proc.debug_event_ep = 0;
                proc.debug_suspend_pending = false;
                proc.debug_suspended = false;
                proc.debug_breakpoint_count = 0;
            }

            proc.state = ProcessState::Dead;
        }
    }
    // SCHEDULER lock released — now safe to drop handles (channel_close may wake_process)

    // Send ProcessExited debug event and close the event channel
    if debug_event_ep_raw != 0 {
        // SAFETY: debug_event_ep was set via set_process_debug_state which stores
        // one unmanaged reference. We wrap it in OwnedEndpoint for RAII cleanup.
        let debug_ep = unsafe { crate::ipc::OwnedEndpoint::from_raw(debug_event_ep_raw) };
        let mut msg = crate::ipc::Message::new();
        let event = rvos_proto::debug::DebugEvent::ProcessExited { exit_code: 0 };
        msg.len = rvos_wire::to_bytes(&event, &mut msg.data).unwrap_or(0);
        if let Ok(wake) = crate::ipc::channel_send(debug_ep.raw(), msg) {
            if wake != 0 {
                crate::task::wake_process(wake);
            }
        }
        drop(debug_ep); // → channel_close
    }

    // Send exit notification before closing handles (so the receiver wakes up)
    if notify_ep_raw != 0 {
        // SAFETY: exit_notify_ep was set via set_exit_notify_ep which stores
        // one unmanaged reference. We wrap it for RAII cleanup.
        let notify_ep = unsafe { crate::ipc::OwnedEndpoint::from_raw(notify_ep_raw) };
        let mut msg = crate::ipc::Message::new();
        let notif = rvos_proto::process::ExitNotification { exit_code: 0 };
        msg.len = rvos_wire::to_bytes(&notif, &mut msg.data).unwrap_or(0);
        if let Ok(wake) = crate::ipc::channel_send(notify_ep.raw(), msg) {
            if wake != 0 {
                crate::task::wake_process(wake);
            }
        }
        drop(notify_ep); // → channel_close
    }

    // Drop all taken handles — RAII auto-closes channels and dec_refs SHMs
    drop(taken_handles);

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

/// Terminate an arbitrary process by PID. Since this is single-core, the
/// target is guaranteed to be Ready or Blocked (not Running — that's the
/// caller). Cleans up handles, sends exit notification, frees frames.
///
/// Returns Ok(()) on success, Err if the PID is invalid (idle, current, dead,
/// or nonexistent).
pub fn terminate_process(target_pid: usize, exit_code: i32) -> Result<(), &'static str> {
    use crate::mm::address::{PhysPageNum, VirtPageNum, PAGE_SIZE};
    use crate::mm::heap::PGTB_ALLOC;

    // Take handles and cleanup info while holding the lock
    let mut taken_handles: [Option<HandleObject>; crate::task::process::MAX_HANDLES] =
        [const { None }; crate::task::process::MAX_HANDLES];
    let notify_ep_raw: usize;
    let mut debug_event_ep_raw = 0usize;

    // Frame cleanup info
    let pt_frames: alloc::vec::Vec<PhysPageNum, crate::mm::heap::PgtbAlloc>;
    let code_ppn: usize;
    let code_pages: usize;
    let mut ustack_ppn: usize = 0;
    let mut ustack_pages: usize = 0;
    let kstack_base: usize;

    {
        let mut sched = SCHEDULER.lock();
        if target_pid == 0 {
            return Err("cannot kill idle task");
        }
        if target_pid == sched.current {
            return Err("cannot kill self (use terminate_current_process)");
        }
        match sched.processes.get(target_pid) {
            Some(Some(p)) if p.state != ProcessState::Dead => {}
            Some(Some(_)) => return Err("already dead"),
            _ => return Err("pid not found"),
        }

        // Scope the mutable borrow of the process so we can access
        // sched.ready_queue afterwards.
        {
            let proc = sched.processes[target_pid].as_mut().unwrap();

            // Snapshot exit_notify_ep before cleanup
            notify_ep_raw = proc.exit_notify_ep;
            proc.exit_notify_ep = 0;

            // Take handles from the process (RAII ownership transfer)
            for (i, slot) in taken_handles.iter_mut().enumerate().take(crate::task::process::MAX_HANDLES) {
                *slot = proc.take_handle(i);
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
                let stack_top_ppn = proc.user_stack_top / PAGE_SIZE;
                ustack_ppn = match stack_top_ppn.checked_sub(ustack_pages) {
                    Some(ppn) => ppn,
                    None => { ustack_pages = 0; 0 }
                };
            }

            // Snapshot debug state for cleanup after lock release
            if proc.debug_attached {
                debug_event_ep_raw = proc.debug_event_ep;
                proc.debug_attached = false;
                proc.debug_event_ep = 0;
                proc.debug_suspend_pending = false;
                proc.debug_suspended = false;
                proc.debug_breakpoint_count = 0;
            }

            // Clear wake_deadline and wakeup_pending
            proc.wake_deadline = 0;
            proc.wakeup_pending = false;

            // Mark state = Dead and snapshot kernel stack base
            proc.state = ProcessState::Dead;
            kstack_base = proc.kernel_stack_base;
            proc.kernel_stack_base = 0;
        }

        // Remove from ready_queue if present
        sched.ready_queue.retain(|&pid| pid != target_pid);
    }
    // SCHEDULER lock released

    // Clear any stale blocked registrations in channels
    crate::ipc::channel_clear_blocked_pid(target_pid);

    // Free kernel stack (safe because target is not running on it)
    if kstack_base != 0 {
        let guard_addr = kstack_base - super::process::KERNEL_GUARD_PAGES * crate::mm::address::PAGE_SIZE;
        super::process::restore_guard_page(guard_addr);
        let alloc_ppn = guard_addr / crate::mm::address::PAGE_SIZE;
        for j in 0..super::process::KERNEL_STACK_ALLOC_PAGES {
            crate::mm::frame::frame_dealloc(
                crate::mm::address::PhysPageNum(alloc_ppn + j),
            );
        }
    }

    // Send ProcessExited debug event and close the event channel
    if debug_event_ep_raw != 0 {
        let debug_ep = unsafe { crate::ipc::OwnedEndpoint::from_raw(debug_event_ep_raw) };
        let mut msg = crate::ipc::Message::new();
        let event = rvos_proto::debug::DebugEvent::ProcessExited { exit_code };
        msg.len = rvos_wire::to_bytes(&event, &mut msg.data).unwrap_or(0);
        if let Ok(wake) = crate::ipc::channel_send(debug_ep.raw(), msg) {
            if wake != 0 {
                crate::task::wake_process(wake);
            }
        }
        drop(debug_ep);
    }

    // Send exit notification
    if notify_ep_raw != 0 {
        let notify_ep = unsafe { crate::ipc::OwnedEndpoint::from_raw(notify_ep_raw) };
        let mut msg = crate::ipc::Message::new();
        let notif = rvos_proto::process::ExitNotification { exit_code };
        msg.len = rvos_wire::to_bytes(&notif, &mut msg.data).unwrap_or(0);
        if let Ok(wake) = crate::ipc::channel_send(notify_ep.raw(), msg) {
            if wake != 0 {
                crate::task::wake_process(wake);
            }
        }
        drop(notify_ep);
    }

    // Drop all taken handles — RAII auto-closes channels and dec_refs SHMs
    drop(taken_handles);

    // Free physical frames (code, user stack, page table nodes)
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
    for &frame in &pt_frames {
        crate::mm::frame::frame_dealloc(frame);
    }
    drop(pt_frames);

    Ok(())
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

/// Check all blocked processes for expired timer deadlines.
/// Called from timer_tick() — runs with interrupts disabled (inside trap handler).
pub fn check_deadlines(now: u64) {
    let mut sched = SCHEDULER.lock();
    for pid in 1..sched.processes.len() {
        let should_wake = if let Some(ref proc) = sched.processes[pid] {
            proc.state == ProcessState::Blocked
                && proc.wake_deadline != 0
                && now >= proc.wake_deadline
        } else {
            false
        };
        if should_wake {
            if let Some(ref mut proc) = sched.processes[pid] {
                proc.wake_deadline = 0;
                proc.state = ProcessState::Ready;
                proc.block_reason = crate::task::process::BlockReason::None;
            }
            sched.ready_queue.push_back(pid);
        }
    }
}

/// Block a process until a deadline (rdtime tick value).
/// If the deadline has already passed, the process is not blocked.
/// If the deadline is sooner than the next regular timer tick,
/// re-arms the SBI timer for a precise wakeup.
pub fn block_with_deadline(pid: usize, deadline_tick: u64) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        if proc.wakeup_pending {
            proc.wakeup_pending = false;
            return;
        }
        let now = crate::task::process::rdtime();
        if now >= deadline_tick {
            // Deadline already passed — don't block
            return;
        }
        proc.state = ProcessState::Blocked;
        proc.block_reason = crate::task::process::BlockReason::Timer(deadline_tick);
        proc.wake_deadline = deadline_tick;
        drop(sched);
        // Re-arm SBI timer to fire early if deadline < next regular tick
        if deadline_tick < now + TIMER_INTERVAL {
            crate::arch::sbi::sbi_set_timer(deadline_tick);
        }
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

/// Unconditionally set a process to Blocked state, ignoring `wakeup_pending`.
/// Used by the debugger's suspend/breakpoint paths where the block is
/// unconditional — any pending IPC wakeup is irrelevant because the process
/// must stop for inspection. The IPC message remains in the channel queue
/// and will be picked up when the debugger resumes the process.
pub fn force_block_process(pid: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        proc.wakeup_pending = false;
        proc.state = ProcessState::Blocked;
    }
}

/// Set the block reason for a process (call before block_process).
pub fn set_block_reason(pid: usize, reason: crate::task::process::BlockReason) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        proc.block_reason = reason;
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
            proc.block_reason = crate::task::process::BlockReason::None;
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
    let _ = writeln!(out, "  PID  STATE     CPU1s  CPU1m  MEM     BLOCKED ON     NAME");
    let _ = writeln!(out, "  ---  --------  -----  -----  ------  -------------  ----------------");
    for (i, slot) in sched.processes.iter().enumerate() {
        if let Some(proc) = slot {
            let state = match proc.state {
                ProcessState::Ready => "Ready   ",
                ProcessState::Running => "Running ",
                ProcessState::Blocked => "Blocked ",
                ProcessState::Dead => "Dead    ",
            };
            let blocked_on = match proc.block_reason {
                crate::task::process::BlockReason::None => String::new(),
                crate::task::process::BlockReason::IpcRecv(ep) => {
                    alloc::format!("recv(ep {})", ep)
                }
                crate::task::process::BlockReason::IpcSend(ep) => {
                    alloc::format!("send(ep {})", ep)
                }
                crate::task::process::BlockReason::Timer(deadline) => {
                    let remaining = deadline.saturating_sub(now) / 10_000; // ms at 10MHz
                    alloc::format!("timer(+{}ms)", remaining)
                }
                crate::task::process::BlockReason::Poll => String::from("poll"),
                crate::task::process::BlockReason::DebugSuspend => String::from("debug"),
            };
            let (e1s, e1m) = effective_ewma(proc, now, i == current_pid, last_switch);
            let mem_kb = proc.mem_pages as usize * 4; // 4 KiB per page
            let _ = writeln!(out, "  {:3}  {}  {:2}.{:<1}%  {:2}.{:<1}%  {:>4}K  {:<13}  {}",
                i, state,
                e1s / 100, (e1s / 10) % 10,
                e1m / 100, (e1m / 10) % 10,
                mem_kb,
                blocked_on,
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

// ============================================================
// Debug accessors (used by process-debug service + trap handler)
// ============================================================

/// Check if a PID is a user process.
pub fn process_is_user(pid: usize) -> bool {
    let sched = SCHEDULER.lock();
    matches!(sched.processes.get(pid), Some(Some(p)) if p.is_user && p.state != ProcessState::Dead)
}

/// Check if a process has a debugger attached.
pub fn process_debug_attached(pid: usize) -> bool {
    let sched = SCHEDULER.lock();
    matches!(sched.processes.get(pid), Some(Some(p)) if p.debug_attached)
}

/// Set or clear the debug-attached state for a process.
pub fn set_process_debug_state(pid: usize, attached: bool, event_ep: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        proc.debug_attached = attached;
        proc.debug_event_ep = event_ep;
        if !attached {
            proc.debug_suspend_pending = false;
            proc.debug_suspended = false;
        }
    }
}

/// Set the debug_suspend_pending flag for a process.
pub fn set_debug_suspend_pending(pid: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        proc.debug_suspend_pending = true;
    }
}

/// Check and clear the debug_suspend_pending flag for the current process.
/// Returns the event endpoint to notify if pending was set.
pub fn check_and_clear_debug_suspend(pid: usize) -> Option<usize> {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        if proc.debug_suspend_pending {
            proc.debug_suspend_pending = false;
            return Some(proc.debug_event_ep);
        }
    }
    None
}

/// Mark a process as debug-suspended.
pub fn mark_debug_suspended(pid: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        proc.debug_suspended = true;
    }
}

/// Clear the debug-suspended flag.
pub fn clear_debug_suspended(pid: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        proc.debug_suspended = false;
    }
}

/// Read the saved TrapFrame for a suspended process.
/// Returns None if process doesn't exist or isn't suspended.
pub fn read_debug_trap_frame(pid: usize) -> Option<TrapFrame> {
    let sched = SCHEDULER.lock();
    match sched.processes.get(pid)?.as_ref() {
        Some(proc) if proc.debug_suspended => Some(proc.trap_ctx.frame),
        _ => None,
    }
}

/// Write a single register in a suspended process's TrapFrame.
/// reg 0-31 = GPR x0-x31; returns false if invalid.
pub fn write_debug_register(pid: usize, reg: u8, value: usize) -> bool {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        if proc.debug_suspended && (reg as usize) < 32 {
            proc.trap_ctx.frame.regs[reg as usize] = value;
            return true;
        }
    }
    false
}

/// Write sepc for a suspended process.
pub fn write_debug_sepc(pid: usize, value: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        if proc.debug_suspended {
            proc.trap_ctx.frame.sepc = value;
        }
    }
}

/// Get user_satp for a specific process (not just the current one).
pub fn process_user_satp_by_pid(pid: usize) -> usize {
    let sched = SCHEDULER.lock();
    match sched.processes.get(pid) {
        Some(Some(proc)) => proc.user_satp,
        _ => 0,
    }
}

/// Get the debug event endpoint for a process (for trap handler use).
pub fn process_debug_event_ep(pid: usize) -> Option<usize> {
    let sched = SCHEDULER.lock();
    match sched.processes.get(pid) {
        Some(Some(proc)) if proc.debug_attached && proc.debug_event_ep != 0 => {
            Some(proc.debug_event_ep)
        }
        _ => None,
    }
}

/// Read the breakpoint table for a process.
pub fn process_debug_breakpoints(pid: usize) -> ([(usize, u16); 8], usize) {
    let sched = SCHEDULER.lock();
    match sched.processes.get(pid) {
        Some(Some(proc)) => (proc.debug_breakpoints, proc.debug_breakpoint_count),
        _ => ([(0, 0); 8], 0),
    }
}

/// Write the breakpoint table for a process.
pub fn set_process_debug_breakpoints(
    pid: usize,
    bp: [(usize, u16); 8],
    count: usize,
) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes.get_mut(pid).and_then(|s| s.as_mut()) {
        proc.debug_breakpoints = bp;
        proc.debug_breakpoint_count = count;
    }
}

