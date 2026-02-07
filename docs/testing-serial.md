# Testing rvOS Serial Console with `expect`

When testing rvOS interactively from CI or scripts, piping stdin directly to
`make run` does not work reliably — the shell may not be ready to receive input
by the time the pipe sends data. Use `expect` (Tcl-based tool for automating
interactive programs) instead.

## Prerequisites

```bash
# Install expect (usually pre-installed on Ubuntu/Debian)
sudo apt install expect
```

## Basic Pattern

Create a `.exp` file:

```tcl
#!/usr/bin/expect -f
set timeout 30
log_user 1

spawn make run

# Wait for the shell prompt before sending commands
expect "rvos>"
send "ps\r"

# Wait for next prompt (output is between the two prompts)
expect "rvos>"
send "shutdown\r"

# Wait for QEMU to exit
expect eof
```

Run it:

```bash
. ~/.cargo/env && timeout 60 expect test.exp
```

## Key Points

1. **Always `expect` the prompt** (`rvos>`) before sending a command. This
   ensures the shell is ready to receive input.

2. **Use `\r` not `\n`** — `send` needs carriage return for serial terminals.

3. **Wrap with `timeout`** — `expect` itself has a per-pattern timeout (`set
   timeout 30`), but wrap the entire command in `timeout 60` as a safety net
   so your CI script never hangs.

4. **Don't pipe stdin** — `echo "ps" | make run` races with boot. The shell
   isn't ready when the data arrives, so it's silently lost or corrupted.

5. **Don't pipe stdout through `tail`** — QEMU may hang if stdout is a pipe
   that breaks. Capture to a file instead if you need to post-process.

## Extracting Output

To programmatically check the output:

```bash
# Run and capture all output, then grep
. ~/.cargo/env && timeout 60 expect test.exp 2>&1 | strings | grep "pattern"

# Or capture to file
. ~/.cargo/env && timeout 60 expect test.exp > output.txt 2>&1
grep "pattern" output.txt
```

Note: expect output may contain ANSI escape codes and binary data from the
build step. Pipe through `strings` to clean it up before grepping.

## Testing Shutdown

The shutdown command (`SYS_SHUTDOWN` → SBI shutdown) causes QEMU to exit with
code 0. You can verify this:

```tcl
expect "rvos>"
send "shutdown\r"
expect {
    "System shutdown" { puts "\nSHUTDOWN OK" }
    timeout { puts "\nTIMEOUT - shutdown failed" }
}
expect eof
```

## Longer Interactive Tests

For multi-step tests (e.g., create file, read it back, verify):

```tcl
expect "rvos>"
send "write /tmp/test.txt hello\r"
expect "rvos>"
send "cat /tmp/test.txt\r"
expect {
    "hello" { puts "\nFILE CONTENT OK" }
    timeout { puts "\nFILE READ FAILED" }
}
expect "rvos>"
send "shutdown\r"
expect eof
```

## Common Pitfalls

| Problem | Cause | Fix |
|---------|-------|-----|
| Command not executed | Didn't wait for `rvos>` | Add `expect "rvos>"` before `send` |
| Garbled output | Binary build output mixed in | Pipe through `strings` |
| Test hangs forever | No outer `timeout` | Wrap with `timeout 60 expect ...` |
| Empty stdin | Used pipe instead of expect | Use expect script |
| QEMU hangs | Piped stdout through `tail` | Capture to file, don't pipe |
