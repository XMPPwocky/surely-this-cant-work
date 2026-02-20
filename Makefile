KERNEL_ELF = target/riscv64gc-unknown-none-elf/release/kernel
KERNEL_BIN = target/riscv64gc-unknown-none-elf/release/kernel.bin
HOST_TRIPLE = $(shell . $$HOME/.cargo/env && rustc -vV | sed -n 's/host: //p')
RUST_TOOLCHAIN_BIN = $(shell . $$HOME/.cargo/env && rustc --print sysroot)/lib/rustlib/$(HOST_TRIPLE)/bin
OBJCOPY = $(RUST_TOOLCHAIN_BIN)/rust-objcopy

# build-std flags (moved out of .cargo/config.toml to avoid leaking into x.py)
BUILD_STD = -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

# Common cargo flags for user-space builds
USER_CARGO = . $$HOME/.cargo/env && cargo +rvos
USER_TARGET = --target riscv64gc-unknown-rvos
USER_MANIFEST = --manifest-path user/Cargo.toml
USER_BIN_DIR = user/target/riscv64gc-unknown-rvos/release

# QEMU lockfile wrapper — ensures only one QEMU instance at a time
QEMU_LOCK = scripts/qemu-lock.sh

# VirtIO net device via TAP (requires: sudo scripts/net-setup.sh)
QEMU_NET = -device virtio-net-device,netdev=net0 -netdev tap,id=net0,ifname=rvos-tap0,script=no,downscript=no

# VirtIO block devices: bin.img (RO), persist.img (RW)
# NOTE: QEMU virt assigns MMIO slots high-to-low per command-line order,
# but the kernel probes low-to-high.  List devices in REVERSE order so
# that the first-listed drive gets the highest slot and the last-listed
# drive gets the lowest slot (discovered first → blk0).
QEMU_BLK = -drive file=persist.img,format=raw,id=blk1,if=none \
           -device virtio-blk-device,drive=blk1 \
           -drive file=bin.img,format=raw,id=blk0,if=none,readonly=on \
           -device virtio-blk-device,drive=blk0

# For test: add a third drive (test.img, freshly mkfs'd)
QEMU_BLK_TEST = -drive file=test.img,format=raw,id=blk2,if=none \
           -device virtio-blk-device,drive=blk2 \
           $(QEMU_BLK)

# User-space binaries to include in bin.img (ext2 filesystem)
EXT2_BINS = hello winclient ipc-torture fbcon triangle gui-bench dbg \
            net-stack udp-echo window-server bench tcp-echo nc ktest ktest-helper shell

.PHONY: build build-user build-fs build-std-lib run run-gui run-vnc run-gpu-screenshot debug clean bench gui-bench run-test test bench-save bench-check clippy clippy-kernel clippy-user disk-images

# Build all user crates except fs (which embeds the others via include_bytes!)
build-user:
	$(USER_CARGO) build --release $(USER_MANIFEST) $(USER_TARGET) --workspace --exclude fs

# fs embeds user binaries via include_bytes!, so build the rest first
build-fs: build-user
	$(USER_CARGO) build --release $(USER_MANIFEST) $(USER_TARGET) -p fs

# Rebuild the rvOS std library + clippy via x.py.
# Run after modifying vendor/rust/library/ or lib/rvos-wire/ or lib/rvos-proto/.
#
# Dependency chain:
#   lib/rvos, lib/rvos-wire, lib/rvos-proto  (canonical sources)
#     ↓  symlinked into vendor/rust/library/ via:
#     ↓    vendor/rust/library/rvos       -> ../../../lib/rvos
#     ↓    vendor/rust/library/rvos-wire  -> ../../../lib/rvos-wire
#     ↓    vendor/rust/library/rvos-proto -> ../../../lib/rvos-proto
#     ↓
#   vendor/rust/library/std  (Rust std with rvos PAL)
#     ↓  std/Cargo.toml depends on rvos-wire + rvos-proto for cfg(target_os="rvos")
#     ↓  std/src/sys/pal/rvos/ implements the platform abstraction layer
#     ↓
#   x.py build library + clippy  →  installed into the 'rvos' toolchain
#     ↓
#   user/ crates build with `cargo +rvos --target riscv64gc-unknown-rvos`
#
# Both std and clippy must be built together so x.py doesn't remove one
# when installing the other.
build-std-lib:
	cd vendor/rust && BOOTSTRAP_SKIP_TARGET_SANITY=1 \
		python3 x.py build src/tools/clippy library --target riscv64gc-unknown-rvos --keep-stage 0

# --- Disk images ---

bin.img: build-user
	dd if=/dev/zero of=$@ bs=1M count=16 2>/dev/null
	mkfs.ext2 -q $@
	for bin in $(EXT2_BINS); do \
		if [ -f $(USER_BIN_DIR)/$$bin ]; then \
			debugfs -w -R "write $(USER_BIN_DIR)/$$bin $$bin" $@ 2>/dev/null; \
		fi; \
	done

persist.img:
	@if [ ! -f $@ ]; then \
		dd if=/dev/zero of=$@ bs=1M count=16 2>/dev/null; \
		mkfs.ext2 -q $@; \
	fi

test.img:
	dd if=/dev/zero of=$@ bs=1M count=4 2>/dev/null
	mkfs.ext2 -q $@

# Build all disk images
disk-images: bin.img persist.img

build: build-fs disk-images
	. $$HOME/.cargo/env && cargo build --release --manifest-path kernel/Cargo.toml \
		--target riscv64gc-unknown-none-elf $(BUILD_STD)
	$(OBJCOPY) --binary-architecture=riscv64 $(KERNEL_ELF) --strip-all -O binary $(KERNEL_BIN)

run: build
	$(QEMU_LOCK) --info "make run" -- qemu-system-riscv64 -machine virt -nographic -serial mon:stdio \
		-bios default -m 128M \
		-device virtio-keyboard-device \
		$(QEMU_NET) \
		$(QEMU_BLK) \
		-kernel $(KERNEL_BIN)

run-gui: build
	$(QEMU_LOCK) --info "make run-gui" -- qemu-system-riscv64 -machine virt -serial stdio \
		-bios default -m 128M \
		-device virtio-gpu-device \
		-device virtio-keyboard-device \
		-device virtio-tablet-device \
		$(QEMU_NET) \
		$(QEMU_BLK) \
		-display gtk \
		-kernel $(KERNEL_BIN)

# VNC mode: connect with a VNC client to :5900, serial on stdio
run-vnc: build
	$(QEMU_LOCK) --info "make run-vnc" -- qemu-system-riscv64 -machine virt -serial stdio \
		-bios default -m 128M \
		-device virtio-gpu-device \
		-device virtio-keyboard-device \
		-device virtio-tablet-device \
		$(QEMU_NET) \
		$(QEMU_BLK) \
		-display vnc=:0 \
		-kernel $(KERNEL_BIN)

# Headless GPU with screenshot via monitor socket
DELAY ?= 5
SCREENSHOT ?= /tmp/rvos-screenshot.ppm
run-gpu-screenshot: build
	@echo "Starting QEMU with virtio-gpu (headless)..."
	$(QEMU_LOCK) --info "make run-gpu-screenshot" -- qemu-system-riscv64 -machine virt -nographic \
		-serial mon:stdio \
		-bios default -m 128M \
		-device virtio-gpu-device \
		-device virtio-keyboard-device \
		-device virtio-tablet-device \
		$(QEMU_NET) \
		$(QEMU_BLK) \
		-display vnc=:0 \
		-kernel $(KERNEL_BIN) \
		-monitor unix:/tmp/qemu-monitor.sock,server,nowait &
	@sleep $(DELAY)
	@echo "Taking screenshot to $(SCREENSHOT)..."
	@echo "screendump $(SCREENSHOT)" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock 2>/dev/null || true
	@sleep 1
	@kill %1 2>/dev/null || true
	@[ -f $(SCREENSHOT) ] && echo "Screenshot saved: $(SCREENSHOT)" || echo "Screenshot failed (install socat?)"

debug: build
	$(QEMU_LOCK) --info "make debug" -- qemu-system-riscv64 -machine virt -nographic -serial mon:stdio \
		-bios default -m 128M \
		-device virtio-keyboard-device \
		$(QEMU_NET) \
		$(QEMU_BLK) \
		-kernel $(KERNEL_BIN) \
		-s -S &
	gdb-multiarch -ex "target remote :1234" -ex "file $(KERNEL_ELF)"

clean:
	. $$HOME/.cargo/env && cargo clean --manifest-path kernel/Cargo.toml
	. $$HOME/.cargo/env && cargo +rvos clean --manifest-path user/Cargo.toml
	rm -f $(KERNEL_BIN) bin.img test.img

bench: build
	@echo "Running rvOS benchmarks..."
	@expect scripts/bench.exp

gui-bench: build
	@echo "Running rvOS GUI benchmarks..."
	@expect scripts/gui-bench.exp

run-test: build test.img
	$(QEMU_LOCK) --info "make run-test" -- qemu-system-riscv64 -machine virt -nographic -serial mon:stdio \
		-bios default -m 128M \
		-device virtio-keyboard-device \
		$(QEMU_BLK_TEST) \
		-kernel $(KERNEL_BIN)

test: build test.img
	@echo "Running rvOS kernel tests..."
	@expect scripts/test.exp

bench-save: build
	@echo "Running benchmarks and saving baseline..."
	@expect scripts/bench-save.exp

bench-check: build
	@echo "Running benchmarks and checking for regressions..."
	@expect scripts/bench-run.exp > /tmp/rvos-bench-output.txt
	@scripts/check-bench-regression.sh bench-baseline.txt /tmp/rvos-bench-output.txt

# --- Clippy ---

clippy-kernel:
	cargo clippy --release --manifest-path kernel/Cargo.toml \
		--target riscv64gc-unknown-none-elf $(BUILD_STD) -- -W clippy::all

clippy-user:
	$(USER_CARGO) clippy --release $(USER_MANIFEST) $(USER_TARGET) \
		--workspace -- -W clippy::all

clippy: clippy-kernel clippy-user
