# rvOS Benchmark Suite

## Overview

The benchmark suite (`/bin/bench`) exercises key rvOS subsystems to provide
baseline performance numbers and detect regressions. It runs as a user-space
process and prints results to serial.

## Running

```bash
make bench          # builds, boots QEMU, runs benchmarks, shuts down
```

Or manually from the serial shell:

```
rvos> run /bin/bench
```

## Benchmarks

| Benchmark             | What it measures                          | Iters |
|-----------------------|-------------------------------------------|-------|
| syscall (getpid)      | Raw ecall round-trip overhead             | 10000 |
| yield                 | Scheduler yield + re-schedule             | 100   |
| chan create+close      | Channel pair create + destroy lifecycle    | 1000  |
| ipc round-trip         | Send + recv on same-process channel pair   | 1000  |
| ipc throughput 1KB     | 1000-byte messages, reports MB/s          | 1000  |
| mmap+munmap 4K         | Allocate + free one 4K anonymous page     | 100   |
| file create+write 64B  | Create file + write 64 bytes (via std::fs) | 20   |
| file read 64B          | Read 64-byte file (via std::fs)           | 20    |
| file stat              | Stat a file (via std::fs)                 | 20    |
| file delete            | Delete files (via std::fs)                | 20    |
| readdir small (10)     | Readdir with 10 entries                   | 20    |
| readdir large (30)     | Create 30 files, readdir                  | 3     |
| process spawn          | Spawn /bin/hello-std, wait for exit       | 3     |

## Baseline Results (QEMU virt, 128 MiB, 10 MHz rdtime)

```
  Benchmark                 Iters   Total(us)     Per(ns)
  ------------------------ ------  ----------  ----------
  syscall (getpid)         10000       69665        6966
  yield                      100     4934789    49347891
  chan create+close         1000       23644       23644
  ipc round-trip            1000       20680       20680
  ipc throughput 1KB        1000       22616       22616
    => 44 MB/s
  mmap+munmap 4K             100        2623       26237
  file create+write 64B       20     1835846    91792330
  file read 64B               20     4014983   200749195
  file stat                   20     1001779    50088965
  file delete                 20     1001952    50097635
  readdir small (10)          20     1004936    50246800
  readdir large (30)           3      110618    36872700
  process spawn                3     4008501  1336167033

  Wall time: 24059543 us
  CPU time:  389206 us
```

## Key Observations

- **Raw syscall**: ~7 us per ecall round-trip (kernel entry + dispatch + return)
- **IPC**: ~20 us per send+recv on same-process channel (44 MB/s for 1KB messages)
- **Channel lifecycle**: ~24 us to create and destroy a channel pair
- **mmap**: ~26 us for 4K page alloc+free (page table walk + frame alloc)
- **File ops**: ~50-200 ms per operation. This is expected because every std::fs
  operation requires multiple IPC round-trips to the fs server (connect to service,
  open file, read/write, close), each involving context switches.
- **yield**: ~49 ms. This is dominated by the timer-based preemptive scheduler;
  yield puts the task at the back of the ready queue and other tasks run first.
- **Process spawn**: ~1.3s per spawn. Includes ELF loading (228KB over IPC),
  page table setup, stdio initialization, full hello-std test run, and exit cleanup.
- **CPU utilization**: 389ms CPU / 24s wall = 1.6%. Most time is idle (waiting
  for timer ticks between context switches for IPC-heavy file operations).

## Implementation Notes

- **Timing**: All benchmarks use `rdtime` (10 MHz, 100ns resolution). Overall
  run timing uses `SYS_CLOCK` which also returns global CPU ticks.
- **IPC benchmarks**: Use same-process channel pairs (no context switch). This
  measures pure kernel IPC overhead.
- **File benchmarks**: Go through the full IPC path (user -> kernel -> fs server
  -> kernel -> user). Measures end-to-end file I/O performance.
- **Process spawn**: Uses the boot channel Spawn protocol. Includes ELF loading,
  page table setup, stdio initialization, program execution, and exit.
- **Cleanup**: Temp files are deleted after each benchmark. The process calls
  `sys_shutdown()` at the end.

## Using for Regression Detection

Run `make bench` before and after changes. Compare per-iteration ns values.
Significant regressions (>20% slower) warrant investigation. Some variance is
expected due to QEMU timer emulation.
