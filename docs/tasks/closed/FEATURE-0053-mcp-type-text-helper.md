# 0053: MCP server: add qemu_type_text helper

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** scripts/qemu-mcp

## Description

The `qemu_send_key` MCP tool only accepts individual QKeyCodes (e.g.,
`"shift-a"`, `"ret"`). Typing a string like `"triangle"` in the GUI
terminal requires 9 separate tool calls, one per character. This is slow
and tedious.

## Proposed Solution

Add a `qemu_type_text(text: str, delay: int = 50)` tool that:

1. Takes an arbitrary ASCII string
2. Maps each character to the appropriate QKeyCode(s) — e.g., `'A'` becomes
   `shift-a`, `'!'` becomes `shift-1`, `' '` becomes `spc`, etc.
3. Sends each key via QMP `send-key` with a small inter-key delay (default
   50ms) to avoid dropped keys
4. Handles common special characters: space, enter, tab, punctuation

This would reduce typing `"triangle\n"` from 10 tool calls to 1.

## Files

- `scripts/qemu-mcp/server.py` — add `type_text()` method to QemuManager
  and register `qemu_type_text` MCP tool

## Notes

Character-to-QKeyCode mapping reference:
- Letters: `a`-`z` (lowercase) / `shift-a` through `shift-z` (uppercase)
- Digits: `1`-`9`, `0`
- Space: `spc`
- Enter: `ret`
- Common punctuation: `minus`, `equal`, `shift-1` (!) etc.
- See QEMU source `ui/input-keymap.c` for the full mapping
