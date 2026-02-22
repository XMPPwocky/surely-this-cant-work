# 0014: QEMU MCP Server for Agent Interaction

**Date:** 2026-02-22
**Status:** Complete (2026-02-22)
**Subsystem:** scripts/qemu-mcp

## Motivation

All QEMU testing currently uses expect scripts (`.exp` files). These work for
scripted test sequences but are inflexible for open-ended debugging or
exploratory interaction. An MCP server wrapping QEMU gives Claude subagents
structured tools to boot the system, interact with the serial console, take
screenshots, send input events, capture network traffic, and talk to the QEMU
monitor — all dynamically, reasoning about what they see.

## Design

### Overview

A Python MCP server (`scripts/qemu-mcp/`) using the `mcp` SDK (stdio
transport). Claude Code connects to it as a local MCP server. The server
manages a single QEMU instance and exposes tools for interaction.

### Architecture

```
Claude Code  <--stdio-->  MCP Server (Python)
                              |
                              |--- named pipe .in/.out ---> QEMU serial
                              |--- QMP unix socket -------> QEMU monitor
                              |--- tcpdump subprocess ----> PCAP file
                              |--- screendump file -------> screenshot
```

The MCP server is a single-process async Python program:
- Uses `asyncio` for non-blocking I/O on pipes and QMP socket
- Manages one QEMU instance at a time (enforced)
- Integrates with `qemu-lock.sh` for project-wide QEMU locking
- Cleans up all resources on shutdown (FIFOs, sockets, child processes)

### QEMU Launch Configuration

QEMU is launched with:
- **Serial** via named pipes (`-chardev pipe`) — preserves boot output in
  kernel pipe buffer, no data loss
- **Monitor** via QMP over Unix socket (`-qmp unix:...`) — structured JSON
  protocol for screenshots, input injection, machine control
- **Display** via VNC (`-display vnc=:0`) when GPU is enabled — needed for
  screendump to work
- **Network** via existing TAP setup — tcpdump for PCAP capture

### Serial Pipe Details

- QEMU `-chardev pipe,id=ser0,path=/tmp/rvos-serial` creates `.in` / `.out`
- Server creates FIFOs before launching QEMU
- Server reads `.out` continuously, buffers output
- Server opens `.in` to write commands, appends `\r`

### QMP Details

- QEMU `-qmp unix:/tmp/rvos-qmp.sock,server=on,wait=off`
- Server connects after QEMU starts, sends `{"execute":"qmp_capabilities"}`
- Uses QMP for: screendump, send-key, input-send-event, query-status, quit
- QMP is JSON over Unix socket — one request per line, async events

### MCP Tools

| Tool | Purpose |
|------|---------|
| `qemu_boot` | Start QEMU with configurable options (gpu, network, drives, memory) |
| `qemu_send` | Send command to serial console, wait for response |
| `qemu_read` | Read current serial output without sending |
| `qemu_screenshot` | Take VNC display screenshot (requires gpu=true) |
| `qemu_send_key` | Send keyboard input via QMP |
| `qemu_mouse` | Send mouse events via QMP |
| `qemu_monitor` | Send raw QMP command |
| `qemu_pcap_start` | Start network traffic capture |
| `qemu_pcap_stop` | Stop capture, return pcap path |
| `qemu_shutdown` | Graceful shutdown, cleanup resources |
| `qemu_status` | Check if QEMU is running |

### Screenshot Flow

1. Server sends QMP `screendump` to write to temp file
2. Reads the file, base64-encodes it
3. Returns as tool result (Claude can view images natively)
4. Cleans up temp file

## Files

| File | Description |
|------|-------------|
| `scripts/qemu-mcp/server.py` | Main MCP server |
| `scripts/qemu-mcp/qmp.py` | Async QMP client |
| `scripts/qemu-mcp/requirements.txt` | Python dependencies |
| `scripts/qemu-mcp/setup.sh` | Venv creation and dep install |

## Testing

1. `make mcp-setup` creates venv and installs deps
2. `make mcp-server` starts the server
3. Agent can boot, interact, screenshot, and shutdown via MCP tools
4. Existing `make test` / `make test-quick` work unchanged
