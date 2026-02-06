KERNEL_ELF = target/riscv64gc-unknown-none-elf/release/kernel
KERNEL_BIN = target/riscv64gc-unknown-none-elf/release/kernel.bin
RUST_TOOLCHAIN_BIN = $(shell . $$HOME/.cargo/env && rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin
OBJCOPY = $(RUST_TOOLCHAIN_BIN)/rust-objcopy

# build-std flags (moved out of .cargo/config.toml to avoid leaking into x.py)
BUILD_STD = -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

.PHONY: build build-shell build-hello build-std-lib run run-gui run-vnc run-gpu-screenshot debug clean

build-shell:
	. $$HOME/.cargo/env && cargo +rvos build --release \
		--manifest-path user/shell/Cargo.toml \
		--target riscv64gc-unknown-rvos

# Rebuild the rvOS std library via x.py (run after modifying vendor/rust/library/)
build-std-lib:
	cd vendor/rust && BOOTSTRAP_SKIP_TARGET_SANITY=1 \
		python3 x.py build library --target riscv64gc-unknown-rvos --keep-stage 0

build-hello:
	. $$HOME/.cargo/env && cargo +rvos build --release \
		--manifest-path user/hello/Cargo.toml \
		--target riscv64gc-unknown-rvos

build: build-shell build-hello
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
		-display gtk \
		-no-shutdown -no-reboot \
		-kernel $(KERNEL_BIN)

# VNC mode: connect with a VNC client to :5900, serial on stdio
run-vnc: build
	qemu-system-riscv64 -machine virt -serial stdio \
		-bios default -m 128M \
		-device virtio-gpu-device \
		-device virtio-keyboard-device \
		-display vnc=:0 \
		-no-shutdown -no-reboot \
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
	rm -f $(KERNEL_BIN)
	cd user/shell && . $$HOME/.cargo/env && cargo clean 2>/dev/null || true
