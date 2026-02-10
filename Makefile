KERNEL_ELF = target/riscv64gc-unknown-none-elf/release/kernel
KERNEL_BIN = target/riscv64gc-unknown-none-elf/release/kernel.bin
RUST_TOOLCHAIN_BIN = $(shell . $$HOME/.cargo/env && rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin
OBJCOPY = $(RUST_TOOLCHAIN_BIN)/rust-objcopy

# build-std flags (moved out of .cargo/config.toml to avoid leaking into x.py)
BUILD_STD = -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

# Common cargo flags for user-space builds
USER_CARGO = . $$HOME/.cargo/env && cargo +rvos
USER_TARGET = --target riscv64gc-unknown-rvos
USER_MANIFEST = --manifest-path user/Cargo.toml

.PHONY: build build-user build-fs build-std-lib run run-gui run-vnc run-gpu-screenshot debug clean bench gui-bench clippy clippy-kernel clippy-user

# Build all user crates except fs (which embeds the others via include_bytes!)
build-user:
	$(USER_CARGO) build --release $(USER_MANIFEST) $(USER_TARGET) --workspace --exclude fs

# fs embeds user binaries via include_bytes!, so build the rest first
build-fs: build-user
	$(USER_CARGO) build --release $(USER_MANIFEST) $(USER_TARGET) -p fs

# Rebuild the rvOS std library + clippy via x.py (run after modifying vendor/rust/library/)
# Both must be built together so x.py doesn't remove one when installing the other.
build-std-lib:
	cd vendor/rust && BOOTSTRAP_SKIP_TARGET_SANITY=1 \
		python3 x.py build src/tools/clippy library --target riscv64gc-unknown-rvos --keep-stage 0

build: build-fs
	. $$HOME/.cargo/env && cargo build --release --manifest-path kernel/Cargo.toml \
		--target riscv64gc-unknown-none-elf $(BUILD_STD)
	$(OBJCOPY) --binary-architecture=riscv64 $(KERNEL_ELF) --strip-all -O binary $(KERNEL_BIN)

run: build
	qemu-system-riscv64 -machine virt -nographic -serial mon:stdio \
		-bios default -m 128M \
		-device virtio-keyboard-device \
		-kernel $(KERNEL_BIN)

run-gui: build
	qemu-system-riscv64 -machine virt -serial stdio \
		-bios default -m 128M \
		-device virtio-gpu-device \
		-device virtio-keyboard-device \
		-device virtio-tablet-device \
		-display gtk \
		-kernel $(KERNEL_BIN)

# VNC mode: connect with a VNC client to :5900, serial on stdio
run-vnc: build
	qemu-system-riscv64 -machine virt -serial stdio \
		-bios default -m 128M \
		-device virtio-gpu-device \
		-device virtio-keyboard-device \
		-device virtio-tablet-device \
		-display vnc=:0 \
		-kernel $(KERNEL_BIN)

# Headless GPU with screenshot via monitor socket
DELAY ?= 5
SCREENSHOT ?= /tmp/rvos-screenshot.ppm
run-gpu-screenshot: build
	@echo "Starting QEMU with virtio-gpu (headless)..."
	qemu-system-riscv64 -machine virt -nographic \
		-serial mon:stdio \
		-bios default -m 128M \
		-device virtio-gpu-device \
		-device virtio-keyboard-device \
		-device virtio-tablet-device \
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
	qemu-system-riscv64 -machine virt -nographic -serial mon:stdio \
		-bios default -m 128M \
		-device virtio-keyboard-device \
		-kernel $(KERNEL_BIN) \
		-s -S &
	gdb-multiarch -ex "target remote :1234" -ex "file $(KERNEL_ELF)"

clean:
	. $$HOME/.cargo/env && cargo clean --manifest-path kernel/Cargo.toml
	. $$HOME/.cargo/env && cargo +rvos clean --manifest-path user/Cargo.toml
	rm -f $(KERNEL_BIN)

bench: build
	@echo "Running rvOS benchmarks..."
	@expect scripts/bench.exp

gui-bench: build
	@echo "Running rvOS GUI benchmarks..."
	@expect scripts/gui-bench.exp

# --- Clippy ---

clippy-kernel:
	cargo clippy --release --manifest-path kernel/Cargo.toml \
		--target riscv64gc-unknown-none-elf $(BUILD_STD) -- -W clippy::all

clippy-user:
	$(USER_CARGO) clippy --release $(USER_MANIFEST) $(USER_TARGET) \
		--workspace -- -W clippy::all

clippy: clippy-kernel clippy-user
