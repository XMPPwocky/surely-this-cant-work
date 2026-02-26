#!/usr/bin/env python3
"""
Generate a compact binary symbol table for embedding in the kernel.

Reads the kernel ELF via llvm-objdump, extracts function/label symbols,
and emits a binary file suitable for objcopy --add-section.

Binary format (all little-endian):
  Header:
    count: u32          -- number of entries
  Entries[count] (sorted by addr, each 16 bytes):
    addr:     u64       -- symbol start address
    name_off: u32       -- byte offset into string table
    name_len: u16       -- byte length of name (no NUL)
    _pad:     u16       -- alignment padding
  String table:
    concatenated UTF-8 names (no NUL separators)
"""

import os
import re
import struct
import subprocess
import sys
from pathlib import Path

DEFAULT_KERNEL = "target/riscv64gc-unknown-none-elf/release/kernel"

RUSTUP_OBJDUMP = os.path.expanduser(
    "~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu"
    "/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objdump"
)


def find_objdump():
    if os.path.isfile(RUSTUP_OBJDUMP) and os.access(RUSTUP_OBJDUMP, os.X_OK):
        return RUSTUP_OBJDUMP
    for name in ("llvm-objdump", "objdump"):
        try:
            subprocess.run(
                [name, "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            return name
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    return None


def build_symbol_table(kernel_path, objdump_cmd):
    result = subprocess.run(
        [objdump_cmd, "--syms", kernel_path],
        capture_output=True, text=True, check=True,
    )

    symbols = []

    func_re = re.compile(
        r"^([0-9a-fA-F]+)\s+[lg].*F\s+\.text\s+([0-9a-fA-F]+)\s+(\S+)$"
    )
    label_re = re.compile(
        r"^([0-9a-fA-F]+)\s+[lg]\s+\.text\s+([0-9a-fA-F]+)\s+(\S+)$"
    )

    for line in result.stdout.splitlines():
        line = line.strip()

        m = func_re.match(line)
        if m:
            addr = int(m.group(1), 16)
            name = m.group(3)
            if addr > 0:
                symbols.append((addr, name))
            continue

        m = label_re.match(line)
        if m:
            addr = int(m.group(1), 16)
            name = m.group(3)
            if name.startswith(".L") or name.startswith("$"):
                continue
            if addr > 0:
                symbols.append((addr, name))

    # Deduplicate by address (keep first)
    seen = set()
    deduped = []
    for addr, name in symbols:
        if addr not in seen:
            seen.add(addr)
            deduped.append((addr, name))

    deduped.sort(key=lambda s: s[0])
    return deduped


def emit_binary(symbols, output_path):
    count = len(symbols)

    # Build string table and entry metadata
    strtab = bytearray()
    entries = []

    for addr, name in symbols:
        name_bytes = name.encode("utf-8")
        name_off = len(strtab)
        name_len = len(name_bytes)
        strtab.extend(name_bytes)
        entries.append((addr, name_off, name_len))

    with open(output_path, "wb") as f:
        # Header
        f.write(struct.pack("<I", count))
        # Entries (16 bytes each)
        for addr, name_off, name_len in entries:
            f.write(struct.pack("<QIHxx", addr, name_off, name_len))
        # String table
        f.write(bytes(strtab))

    total_size = 4 + count * 16 + len(strtab)
    return total_size


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate kernel symbol table binary")
    parser.add_argument("--kernel", default=DEFAULT_KERNEL, help="Kernel ELF path")
    parser.add_argument("-o", "--output", required=True, help="Output binary path")
    args = parser.parse_args()

    kernel_path = args.kernel
    if not os.path.isfile(kernel_path):
        project_root = Path(__file__).resolve().parent.parent
        alt = project_root / kernel_path
        if alt.is_file():
            kernel_path = str(alt)
        else:
            print(f"error: kernel ELF not found: {args.kernel}", file=sys.stderr)
            sys.exit(1)

    objdump = find_objdump()
    if not objdump:
        print("error: could not find llvm-objdump or objdump", file=sys.stderr)
        sys.exit(1)

    symbols = build_symbol_table(kernel_path, objdump)
    if not symbols:
        print("warning: no symbols found", file=sys.stderr)

    total_size = emit_binary(symbols, args.output)
    print(f"[gen_symtab] {len(symbols)} symbols, {total_size} bytes -> {args.output}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
