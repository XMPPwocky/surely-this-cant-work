#!/usr/bin/env python3
"""
Symbolize hex addresses from kernel backtrace output.

Reads lines from stdin (or a file argument) containing hex addresses like
ra=0x8020d1ea or bare 0x80201234, resolves each to the nearest kernel
function symbol + offset, and prints the annotated line.

Usage:
    echo "ra=0x8020d1ea" | python3 scripts/symbolize_addresses.py
    python3 scripts/symbolize_addresses.py < crash_log.txt
    python3 scripts/symbolize_addresses.py --kernel path/to/kernel < log.txt
"""

import argparse
import os
import re
import subprocess
import sys
from bisect import bisect_right
from pathlib import Path


# Default kernel ELF path (relative to project root)
DEFAULT_KERNEL = "target/riscv64gc-unknown-none-elf/release/kernel"

# llvm-objdump from the Rust nightly toolchain
RUSTUP_OBJDUMP = os.path.expanduser(
    "~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu"
    "/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objdump"
)


def find_objdump():
    """Find llvm-objdump, preferring the Rust toolchain copy."""
    if os.path.isfile(RUSTUP_OBJDUMP) and os.access(RUSTUP_OBJDUMP, os.X_OK):
        return RUSTUP_OBJDUMP
    # Fall back to PATH
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


def find_demangler():
    """Find a demangler that handles Rust v0 mangling.

    Preference order: rustfilt (in ~/.cargo/bin or PATH), llvm-cxxfilt, c++filt.
    Returns the command path or None if nothing works.

    We test with multiple Rust v0 mangled symbols since some demanglers handle
    only a subset of the v0 encoding.
    """
    test_symbols = [
        "_RNvNtNtCseXInikuqA43_6kernel4task9scheduler32spawn_user_elf_with_boot_channel",
        "_RNvNtCseXInikuqA43_6kernel4main10kernel_main",
    ]

    # Build candidate list with full paths where appropriate
    candidates = []

    # rustfilt from cargo bin
    cargo_rustfilt = os.path.expanduser("~/.cargo/bin/rustfilt")
    if os.path.isfile(cargo_rustfilt) and os.access(cargo_rustfilt, os.X_OK):
        candidates.append(cargo_rustfilt)
    candidates.extend(["rustfilt", "llvm-cxxfilt", "c++filt"])

    for cmd in candidates:
        try:
            input_text = "\n".join(test_symbols)
            result = subprocess.run(
                [cmd],
                input=input_text,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                continue
            outputs = result.stdout.strip().split("\n")
            # Accept if ANY of the test symbols was demangled
            for orig, demangled in zip(test_symbols, outputs):
                if demangled.strip() != orig:
                    return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def demangle_batch(symbols, demangler_cmd):
    """Demangle a list of symbol names in one subprocess call.

    Returns a dict mapping mangled -> demangled.
    """
    if not demangler_cmd or not symbols:
        return {s: s for s in symbols}

    input_text = "\n".join(symbols)
    try:
        result = subprocess.run(
            [demangler_cmd],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            demangled = result.stdout.strip().split("\n")
            if len(demangled) == len(symbols):
                return dict(zip(symbols, [d.strip() for d in demangled]))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: return as-is
    return {s: s for s in symbols}


def build_symbol_table(kernel_path, objdump_cmd):
    """Parse llvm-objdump --syms output into a sorted list of (addr, size, name).

    Includes both function symbols (F flag) and non-function .text symbols
    (asm labels like _start, switch_context) that are useful for symbolization.
    Filters out internal labels (.L*, $x, $d).
    """
    result = subprocess.run(
        [objdump_cmd, "--syms", kernel_path],
        capture_output=True,
        text=True,
        check=True,
    )

    symbols = []

    # Match function symbols: addr flags F section size name
    # Example: 00000000802002d8 l     F .text	0000000000000278 _RNv...
    func_re = re.compile(
        r"^([0-9a-fA-F]+)\s+[lg].*F\s+\.text\s+([0-9a-fA-F]+)\s+(\S+)$"
    )

    # Match non-function .text symbols (asm labels)
    # Example: 0000000080200034 g       .text	0000000000000000 _trap_entry
    label_re = re.compile(
        r"^([0-9a-fA-F]+)\s+[lg]\s+\.text\s+([0-9a-fA-F]+)\s+(\S+)$"
    )

    for line in result.stdout.splitlines():
        line = line.strip()

        m = func_re.match(line)
        if m:
            addr = int(m.group(1), 16)
            size = int(m.group(2), 16)
            name = m.group(3)
            if addr > 0:
                symbols.append((addr, size, name))
            continue

        m = label_re.match(line)
        if m:
            addr = int(m.group(1), 16)
            size = int(m.group(2), 16)
            name = m.group(3)
            # Skip internal labels
            if name.startswith(".L") or name.startswith("$"):
                continue
            if addr > 0:
                symbols.append((addr, size, name))

    # Sort by address
    symbols.sort(key=lambda s: s[0])
    return symbols


def resolve_address(addr, sym_addrs, symbols, demangled):
    """Resolve an address to 'demangled_name+0xoffset' or None."""
    if not symbols:
        return None

    # bisect to find the symbol whose address is <= addr
    idx = bisect_right(sym_addrs, addr) - 1
    if idx < 0:
        return None

    sym_addr, sym_size, sym_name = symbols[idx]
    offset = addr - sym_addr

    # If the symbol has a known size, check that the address falls within it.
    # For zero-size symbols (asm labels), allow a generous range but cap at
    # 64KB to avoid nonsensical matches.
    if sym_size > 0 and offset >= sym_size:
        # Address is past this function. It might be in a gap between
        # functions (e.g., alignment padding). Still show it but flag
        # that it's past the end.
        if offset < 0x10000:
            display = demangled.get(sym_name, sym_name)
            return f"{display}+0x{offset:x} (past end, size=0x{sym_size:x})"
        return None
    elif sym_size == 0 and offset > 0x10000:
        return None

    display = demangled.get(sym_name, sym_name)
    return f"{display}+0x{offset:x}"


def main():
    parser = argparse.ArgumentParser(
        description="Symbolize hex addresses from kernel backtrace output."
    )
    parser.add_argument(
        "--kernel",
        default=DEFAULT_KERNEL,
        help=f"Path to kernel ELF (default: {DEFAULT_KERNEL})",
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=argparse.FileType("r"),
        default=sys.stdin,
        help="Input file (default: stdin)",
    )
    args = parser.parse_args()

    kernel_path = args.kernel
    if not os.path.isfile(kernel_path):
        # Try relative to script directory's parent (project root)
        project_root = Path(__file__).resolve().parent.parent
        alt = project_root / kernel_path
        if alt.is_file():
            kernel_path = str(alt)
        else:
            print(f"error: kernel ELF not found: {args.kernel}", file=sys.stderr)
            print(
                f"  tried: {args.kernel} and {alt}",
                file=sys.stderr,
            )
            sys.exit(1)

    objdump = find_objdump()
    if not objdump:
        print("error: could not find llvm-objdump or objdump", file=sys.stderr)
        sys.exit(1)

    # Build symbol table
    try:
        symbols = build_symbol_table(kernel_path, objdump)
    except subprocess.CalledProcessError as e:
        print(f"error: objdump failed: {e}", file=sys.stderr)
        sys.exit(1)

    if not symbols:
        print("warning: no symbols found in kernel ELF", file=sys.stderr)

    # Demangle all symbol names in one batch
    demangler = find_demangler()
    if demangler:
        print(f"[using demangler: {demangler}]", file=sys.stderr)
    else:
        print("[warning: no Rust demangler found, symbols will be mangled]", file=sys.stderr)
        print("[  install rustfilt: cargo install rustfilt]", file=sys.stderr)
    mangled_names = list(set(s[2] for s in symbols))
    demangled = demangle_batch(mangled_names, demangler)

    # Pre-extract sorted addresses for bisect
    sym_addrs = [s[0] for s in symbols]

    # Regex to find hex addresses in input lines
    # Matches patterns like: 0x8020d1ea, 0x80200034
    hex_re = re.compile(r"0x([0-9a-fA-F]{6,16})")

    # Process input
    for line in args.input:
        line = line.rstrip("\n")
        matches = hex_re.findall(line)
        resolutions = []

        for hex_str in matches:
            addr = int(hex_str, 16)
            resolved = resolve_address(addr, sym_addrs, symbols, demangled)
            if resolved:
                resolutions.append(resolved)

        if resolutions:
            # Deduplicate while preserving order
            seen = set()
            unique = []
            for r in resolutions:
                if r not in seen:
                    seen.add(r)
                    unique.append(r)

            annotation = "  (" + "; ".join(unique) + ")"
            print(line + annotation)
        else:
            print(line)


if __name__ == "__main__":
    main()
