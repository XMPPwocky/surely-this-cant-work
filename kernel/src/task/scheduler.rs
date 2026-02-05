use alloc::collections::VecDeque;
use alloc::vec::Vec;
use alloc::string::String;
use core::fmt::Write;
use crate::sync::SpinLock;
use crate::task::context::TaskContext;
use crate::task::process::{Process, ProcessState, MAX_PROCS};

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

pub fn init() {
    SCHEDULER.lock().init();
    crate::println!("Scheduler initialized (max {} processes)", MAX_PROCS);
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
    // Set the name
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = sched.processes[pid] {
        proc.set_name(name);
    }
    crate::println!("  Spawned [{}] \"{}\" (PID {})", pid, name, pid);
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
}

/// Mark the current task as dead and schedule away
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
