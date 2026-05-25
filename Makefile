# Limnx — Makefile
# Builds a bootable x86_64 ISO using Limine boot protocol

CC       := x86_64-elf-gcc
LD       := x86_64-elf-ld
NASM     := nasm
GCC_INCL := $(shell $(CC) -print-file-name=include 2>/dev/null)
EXTRA_CFLAGS ?=
CFLAGS   := -ffreestanding -nostdinc -isystem $(GCC_INCL) \
            -fno-stack-protector -fno-pic \
            -mno-red-zone -mcmodel=kernel -mno-sse -mno-mmx -mno-sse2 \
            -fno-omit-frame-pointer \
            -Wall -Wextra -O2 -g -MMD -MP \
            -Ikernel/deps -Ikernel/src -Iinclude $(EXTRA_CFLAGS)
LDFLAGS  := -nostdlib -static -T kernel/linker.ld
NASMFLAGS := -f elf64 -g

# User-space C flags: SSE enabled for float math, small code model
USER_CFLAGS := -ffreestanding -nostdinc -isystem $(GCC_INCL) \
               -fno-stack-protector -fno-pic \
               -mno-red-zone -msse -msse2 \
               -Wall -Wextra -O2 -g -MMD -MP \
               -Iuser -Iinclude

KERNEL   := build/kernel
ISO      := limnx.iso

SRCS     := kernel/src/main.c \
            kernel/src/arch/x86_64/serial.c \
            kernel/src/arch/x86_64/gdt.c kernel/src/arch/x86_64/idt.c \
            kernel/src/arch/x86_64/tss.c kernel/src/arch/x86_64/lapic.c \
            kernel/src/arch/x86_64/smp.c kernel/src/arch/x86_64/boot.c \
            kernel/src/mm/pmm.c kernel/src/mm/vmm.c \
            kernel/src/mm/kheap.c \
            kernel/src/mm/dma.c \
            kernel/src/sched/thread.c \
            kernel/src/sched/sched.c \
            kernel/src/syscall/syscall.c \
            kernel/src/syscall/sys_fs.c \
            kernel/src/syscall/sys_proc.c \
            kernel/src/syscall/sys_mm.c \
            kernel/src/syscall/sys_fd.c \
            kernel/src/syscall/sys_net.c \
            kernel/src/syscall/sys_signal.c \
            kernel/src/syscall/sys_ipc.c \
            kernel/src/syscall/sys_security.c \
            kernel/src/syscall/sys_infer.c \
            kernel/src/syscall/sys_misc.c \
            kernel/src/syscall/sys_accel.c \
            kernel/src/accel/virtio_accel_mmio.c \
            kernel/src/proc/process.c kernel/src/proc/elf.c \
            kernel/src/fs/vfs.c kernel/src/fs/tar.c \
            kernel/src/pci/pci.c \
            kernel/src/net/virtio_net.c kernel/src/net/net.c kernel/src/net/tcp.c \
            kernel/src/blk/virtio_blk.c kernel/src/blk/limnfs.c kernel/src/blk/bcache.c \
            kernel/src/net/netstor.c \
            kernel/src/fb/fbcon.c \
            kernel/src/pty/pty.c \
            kernel/src/sync/mutex.c kernel/src/sync/futex.c \
            kernel/src/ipc/unix_sock.c kernel/src/ipc/eventfd.c kernel/src/ipc/agent_reg.c \
            kernel/src/ipc/epoll.c kernel/src/ipc/infer_svc.c kernel/src/ipc/uring.c \
            kernel/src/ipc/cap_token.c kernel/src/ipc/agent_ns.c kernel/src/ipc/taskgraph.c \
            kernel/src/ipc/supervisor.c kernel/src/ipc/pipe.c kernel/src/ipc/shm.c \
            kernel/src/ipc/pubsub.c \
            kernel/src/mm/swap.c
OBJS     := $(patsubst kernel/src/%.c,build/%.o,$(SRCS))

ASM_SRCS := kernel/src/arch/x86_64/isr_stubs.asm \
            kernel/src/arch/x86_64/switch.asm \
            kernel/src/arch/x86_64/syscall_entry.asm
ASM_OBJS := $(patsubst kernel/src/%.asm,build/%.o,$(ASM_SRCS))

# User-space ASM ELF programs (placed in initrd, loaded at runtime)
USER_ASM_ELFS := build/user/asm/hello.elf build/user/asm/cat.elf \
                 build/user/asm/udpecho.elf build/user/asm/writetest.elf

# User-space C libc objects
LIBC_C_SRCS   := user/libc/start.c user/libc/syscalls.c \
                 user/libc/string.c user/libc/stdio.c user/libc/math.c user/libc/tensor.c \
                 user/libc/vecstore.c user/libc/agent.c user/libc/transformer.c \
                 user/libc/tokenizer.c user/libc/gguf.c user/libc/dequant.c \
                 user/libc/http.c user/libc/tooldispatch.c user/libc/malloc.c \
                 user/libc/fio.c user/libc/wasm.c user/libc/accel.c \
                 user/libc/config.c
LIBC_C_OBJS   := $(patsubst user/libc/%.c,build/user/libc/%.o,$(LIBC_C_SRCS))
LIBC_OBJS     := $(LIBC_C_OBJS)

# User-space C ELF programs (linked with libc)
# Limnx-specific daemons and tools. Standard Unix coreutils (echo, ls, cat,
# cp, mv, rm, mkdir, ps, kill, wc, head, tail, grep, chmod, chown, env, mount,
# umount, whoami) are provided by busybox via /bin/<name> symlinks.
USER_C_PROGRAMS := build/user/programs/shell.elf build/user/programs/agent.elf \
                   build/user/programs/agentrt.elf build/user/programs/toolagent.elf \
                   build/user/programs/chat.elf build/user/programs/generate.elf \
                   build/user/programs/learn.elf build/user/programs/infer.elf \
                   build/user/programs/inferd.elf build/user/programs/worker.elf \
                   build/user/programs/multiagent.elf build/user/programs/netagent.elf \
                   build/user/programs/crasher.elf \
                   build/user/programs/serviced.elf \
                   build/user/programs/hello.elf \
                   build/user/programs/init.elf \
                   build/user/programs/login.elf \
                   build/user/programs/orchestrator.elf \
                   build/user/programs/agent_worker.elf \
                   build/user/programs/agentd.elf \
                   build/user/programs/inferd_proxy.elf \
                   build/user/programs/llmchat.elf \
                   build/user/programs/file_reader.elf \
                   build/user/programs/code_executor.elf \
                   build/user/programs/tool_demo.elf \
                   build/user/programs/wasm_runner.elf

# Test programs — organized by subsystem (Linux kselftest model)
USER_C_TESTS := build/user/tests/fs/fs_test.elf \
                build/user/tests/proc/proc_test.elf \
                build/user/tests/mm/mm_test.elf \
                build/user/tests/ipc/ipc_test.elf \
                build/user/tests/net/net_test.elf \
                build/user/tests/security/security_test.elf \
                build/user/tests/system/system_test.elf \
                build/user/tests/infer/infer_test.elf \
                build/user/tests/libc/libc_test.elf \
                build/user/tests/sched/sched_test.elf \
                build/user/tests/arch/x86_64/x86_test.elf \
                build/user/tests/accel/accel_test.elf


USER_C_ELFS := $(USER_C_PROGRAMS) $(USER_C_TESTS)

USER_ELFS := $(USER_ASM_ELFS) $(USER_C_ELFS)

# Initrd (tar archive from initrd/ directory + user ELFs)
INITRD   := build/initrd.tar

# Disk image for virtio-blk
DISK_IMG := build/disk.img

ALL_OBJS := $(OBJS) $(ASM_OBJS)

LIMINE_DIR := build/limine

.PHONY: all clean run deps limine iso disk

all: $(ISO)

# --- Dependencies ---

deps:
	@bash kernel/get-deps.sh

# --- Limine bootloader (binary release branch) ---

$(LIMINE_DIR)/limine:
	@echo "Cloning Limine (binary branch)..."
	git clone --depth 1 --branch v8.x-binary https://github.com/limine-bootloader/limine.git $(LIMINE_DIR)
	$(MAKE) -C $(LIMINE_DIR)

limine: $(LIMINE_DIR)/limine

# --- Kernel ---

build/%.o: kernel/src/%.c | deps
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

build/%.o: kernel/src/%.asm
	@mkdir -p $(dir $@)
	$(NASM) $(NASMFLAGS) $< -o $@

# --- User ASM programs (ELF64, linked with user/linker.ld) ---
# Static pattern rule: only applies to USER_ASM_ELFS, not C programs.

$(patsubst %.elf,%.o,$(USER_ASM_ELFS)): build/user/%.o: user/%.asm user/syscall.inc
	@mkdir -p $(dir $@)
	$(NASM) -f elf64 -I user/ $< -o $@

$(USER_ASM_ELFS): build/user/%.elf: build/user/%.o user/linker.ld
	$(LD) -nostdlib -static -T user/linker.ld $< -o $@

# --- User libc objects ---

build/user/libc/%.o: user/libc/%.c user/libc/libc.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

# --- User C programs (linked with libc) ---
# Pattern rules replace 500+ lines of per-file boilerplate.
# Header deps auto-tracked via -MMD -MP (see -include at bottom).

build/user/%.o: user/%.c
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

build/user/%.elf: build/user/%.o $(LIBC_OBJS) user/arch/x86_64/linker.ld
	$(LD) -nostdlib -static -T user/arch/x86_64/linker.ld $(LIBC_OBJS) $< -o $@

# --- Disk image for virtio-blk ---

$(DISK_IMG):
	@mkdir -p build
	dd if=/dev/zero of=$@ bs=1M count=256 2>/dev/null
	@echo "Created 256MB disk image: $@"

disk: $(DISK_IMG)

# --- Model disk: LimnFS image with GGUF model pre-loaded ---
# Usage: make model-disk MODEL=/path/to/model.gguf
MODEL ?=
model-disk:
	@if [ -z "$(MODEL)" ]; then echo "Usage: make model-disk MODEL=/path/to/model.gguf"; exit 1; fi
	python3 tools/mklimnfs.py -o build/disk.img $(MODEL):model.gguf
	@echo "Model disk ready: build/disk.img"

# --- Initrd (tar archive with user ELFs + data files) ---

$(INITRD): $(USER_ELFS) $(wildcard initrd/*)
	@mkdir -p build/initrd_staging
	cp -f initrd/* build/initrd_staging/ 2>/dev/null || true
	@for f in $(USER_ELFS); do cp -f "$$f" build/initrd_staging/; done
	COPYFILE_DISABLE=1 tar cf $@ --format ustar -C build/initrd_staging .
	rm -rf build/initrd_staging

$(KERNEL): $(ALL_OBJS)
	$(LD) $(LDFLAGS) $(ALL_OBJS) -o $@

# --- ISO ---

$(ISO): $(KERNEL) $(INITRD) $(LIMINE_DIR)/limine
	@echo "Building ISO..."
	@mkdir -p build/iso_root/boot build/iso_root/boot/limine build/iso_root/EFI/BOOT
	cp $(KERNEL) build/iso_root/boot/kernel
	cp $(INITRD) build/iso_root/boot/initrd.tar
	cp limine.conf build/iso_root/boot/limine/limine.conf
	cp $(LIMINE_DIR)/BOOTX64.EFI build/iso_root/EFI/BOOT/BOOTX64.EFI
	cp $(LIMINE_DIR)/BOOTIA32.EFI build/iso_root/EFI/BOOT/BOOTIA32.EFI 2>/dev/null || true
	cp $(LIMINE_DIR)/limine-bios-cd.bin build/iso_root/boot/limine/
	cp $(LIMINE_DIR)/limine-bios.sys build/iso_root/boot/limine/
	cp $(LIMINE_DIR)/limine-uefi-cd.bin build/iso_root/boot/limine/
	xorriso -as mkisofs \
		-R -J \
		-b boot/limine/limine-bios-cd.bin \
		-no-emul-boot -boot-load-size 4 -boot-info-table \
		--efi-boot boot/limine/limine-uefi-cd.bin \
		-efi-boot-part --efi-boot-image --protective-msdos-label \
		build/iso_root -o $(ISO) 2>&1
	$(LIMINE_DIR)/limine bios-install $(ISO)
	@echo "ISO ready: $(ISO)"

iso: $(ISO)

# --- Run in QEMU ---

run: $(ISO) $(DISK_IMG)
	@stty raw -echo 2>/dev/null; \
	qemu-system-x86_64 \
		-M q35 \
		-cdrom $(ISO) \
		-m $(or $(RAM),4G) \
		-smp 2 \
		-serial stdio \
		-display none \
		-no-reboot \
		-device virtio-net-pci,netdev=net0 \
		-netdev user,id=net0,hostfwd=udp::5555-10.0.2.15:1234,hostfwd=tcp::8080-10.0.2.15:80 \
		-drive file=$(DISK_IMG),format=raw,if=none,id=disk0 \
		-device virtio-blk-pci,drive=disk0; \
	stty sane 2>/dev/null

# --- Test (boot + run 'test all' via shell) ---

test:
	@echo "=== Building with RUN_BOOT_TESTS ==="
	$(MAKE) clean
	$(MAKE) EXTRA_CFLAGS=-DRUN_BOOT_TESTS
	$(MAKE) disk
	@echo "=== Running all tests ==="
	qemu-system-x86_64 \
		-M q35 \
		-cdrom $(ISO) \
		-m 4G \
		-smp 2 \
		-serial stdio \
		-display none \
		-no-reboot \
		-device virtio-net-pci,netdev=net0 \
		-netdev user,id=net0 \
		-drive file=$(DISK_IMG),format=raw,if=none,id=disk0 \
		-device virtio-blk-pci,drive=disk0

# --- Auto-generated dependencies ---
-include $(OBJS:.o=.d)
-include $(LIBC_C_OBJS:.o=.d)

# =============================================================
# ARM64 cross-compilation targets
# =============================================================

ARM64_CC     := aarch64-elf-gcc
ARM64_LD     := aarch64-elf-ld
ARM64_AS     := aarch64-elf-as
ARM64_OBJCOPY := aarch64-elf-objcopy

# Fallback to linux-gnu toolchain if elf toolchain not found
ARM64_CC_CHECK := $(shell which $(ARM64_CC) 2>/dev/null)
ifeq ($(ARM64_CC_CHECK),)
ARM64_CC     := aarch64-linux-gnu-gcc
ARM64_LD     := aarch64-linux-gnu-ld
ARM64_AS     := aarch64-linux-gnu-as
ARM64_OBJCOPY := aarch64-linux-gnu-objcopy
endif

ARM64_CFLAGS := -ffreestanding -nostdinc -isystem $(shell $(ARM64_CC) -print-file-name=include 2>/dev/null || echo /dev/null) \
                -fno-stack-protector -fno-pic -mno-outline-atomics \
                -mgeneral-regs-only \
                -Wall -Wextra -O2 -g -MMD -MP \
                -Ikernel/src -Ikernel/deps -Iinclude
ARM64_LDFLAGS := -nostdlib -static -T kernel/src/arch/arm64/linker.ld

ARM64_KERNEL := build/arm64/kernel

ARM64_C_SRCS := kernel/src/arch/arm64/main.c \
                kernel/src/arch/arm64/serial.c \
                kernel/src/arch/arm64/arch_init.c \
                kernel/src/arch/arm64/interrupt.c \
                kernel/src/arch/arm64/timer.c \
                kernel/src/arch/arm64/smp.c \
                kernel/src/arch/arm64/gic.c \
                kernel/src/arch/arm64/syscall_entry.c \
                kernel/src/arch/arm64/stubs.c \
                kernel/src/mm/pmm.c kernel/src/mm/vmm.c \
                kernel/src/mm/kheap.c \
                kernel/src/mm/dma.c \
                kernel/src/dtb/dtb.c \
                kernel/src/sched/thread.c kernel/src/sched/sched.c \
                kernel/src/sync/mutex.c kernel/src/sync/futex.c \
                kernel/src/proc/process.c kernel/src/proc/elf.c \
                kernel/src/fs/vfs.c kernel/src/fs/tar.c \
                kernel/src/pty/pty.c \
                kernel/src/syscall/syscall.c \
                kernel/src/syscall/sys_fs.c \
                kernel/src/syscall/sys_proc.c \
                kernel/src/syscall/sys_mm.c \
                kernel/src/syscall/sys_fd.c \
                kernel/src/syscall/sys_net.c \
                kernel/src/syscall/sys_signal.c \
                kernel/src/syscall/sys_ipc.c \
                kernel/src/syscall/sys_security.c \
                kernel/src/syscall/sys_infer.c \
                kernel/src/syscall/sys_misc.c \
                kernel/src/syscall/sys_accel.c \
                kernel/src/accel/virtio_accel_mmio.c \
                kernel/src/ipc/unix_sock.c kernel/src/ipc/eventfd.c \
                kernel/src/ipc/agent_reg.c kernel/src/ipc/epoll.c \
                kernel/src/ipc/infer_svc.c kernel/src/ipc/uring.c \
                kernel/src/ipc/cap_token.c kernel/src/ipc/agent_ns.c \
                kernel/src/ipc/taskgraph.c kernel/src/ipc/supervisor.c \
                kernel/src/ipc/pipe.c kernel/src/ipc/shm.c \
                kernel/src/ipc/pubsub.c \
                kernel/src/blk/virtio_blk_mmio.c \
                kernel/src/blk/bcache.c kernel/src/blk/limnfs.c \
                kernel/src/net/virtio_net_mmio.c kernel/src/net/net.c \
                kernel/src/net/tcp.c kernel/src/net/netstor.c \
                kernel/src/mm/swap.c \
                kernel/src/fb/fbcon.c \
                kernel/src/fb/virtio_gpu_mmio.c
ARM64_ASM_SRCS := kernel/src/arch/arm64/boot.S \
                  kernel/src/arch/arm64/vectors.S \
                  kernel/src/arch/arm64/ap_boot.S \
                  kernel/src/arch/arm64/switch.S \
                  kernel/src/arch/arm64/usermode.S

ARM64_C_OBJS := $(patsubst kernel/src/%.c,build/arm64/%.o,$(ARM64_C_SRCS))
ARM64_ASM_OBJS := $(patsubst kernel/src/%.S,build/arm64/%.o,$(ARM64_ASM_SRCS))
ARM64_OBJS := $(ARM64_C_OBJS) $(ARM64_ASM_OBJS)

# ARM64 user-space flags (NEON enabled for float math, no -mgeneral-regs-only)
ARM64_USER_CFLAGS := -ffreestanding -nostdinc -isystem $(shell $(ARM64_CC) -print-file-name=include 2>/dev/null || echo /dev/null) \
                     -fno-stack-protector -fno-pic -mno-outline-atomics \
                     -Wall -Wextra -O2 -g -MMD -MP -Iuser -Iinclude

# ARM64 user libc objects
ARM64_LIBC_C_OBJS := $(patsubst user/libc/%.c,build/arm64/user/libc/%.o,$(LIBC_C_SRCS))

# ARM64 user programs — same Limnx-specific set as x86_64; coreutils via busybox.
ARM64_USER_C_PROGRAMS := build/arm64/user/programs/shell.elf \
                          build/arm64/user/programs/serviced.elf \
                          build/arm64/user/programs/hello.elf \
                          build/arm64/user/programs/init.elf \
                          build/arm64/user/programs/login.elf \
                          build/arm64/user/programs/orchestrator.elf \
                          build/arm64/user/programs/agent_worker.elf \
                          build/arm64/user/programs/agentd.elf \
                          build/arm64/user/programs/inferd_proxy.elf \
                          build/arm64/user/programs/inferd.elf \
                          build/arm64/user/programs/infer.elf \
                          build/arm64/user/programs/generate.elf \
                          build/arm64/user/programs/chat.elf \
                          build/arm64/user/programs/agent.elf \
                          build/arm64/user/programs/agentrt.elf \
                          build/arm64/user/programs/toolagent.elf \
                          build/arm64/user/programs/learn.elf \
                          build/arm64/user/programs/worker.elf \
                          build/arm64/user/programs/multiagent.elf \
                          build/arm64/user/programs/netagent.elf \
                          build/arm64/user/programs/crasher.elf \
                          build/arm64/user/programs/file_reader.elf \
                          build/arm64/user/programs/code_executor.elf \
                          build/arm64/user/programs/tool_demo.elf \
                          build/arm64/user/programs/wasm_runner.elf
ARM64_USER_C_TESTS := build/arm64/user/tests/fs/fs_test.elf \
                      build/arm64/user/tests/proc/proc_test.elf \
                      build/arm64/user/tests/mm/mm_test.elf \
                      build/arm64/user/tests/ipc/ipc_test.elf \
                      build/arm64/user/tests/net/net_test.elf \
                      build/arm64/user/tests/security/security_test.elf \
                      build/arm64/user/tests/system/system_test.elf \
                      build/arm64/user/tests/infer/infer_test.elf \
                      build/arm64/user/tests/libc/libc_test.elf \
                      build/arm64/user/tests/sched/sched_test.elf \
                      build/arm64/user/tests/arch/arm64/arm64_test.elf \
                      build/arm64/user/tests/accel/accel_test.elf
ARM64_USER_C_ELFS := $(ARM64_USER_C_PROGRAMS) $(ARM64_USER_C_TESTS)

# ARM64 initrd
ARM64_INITRD := build/arm64/initrd.tar

.PHONY: arm64 arm64-run arm64-clean

# ARM64 kernel C compilation
build/arm64/%.o: kernel/src/%.c
	@mkdir -p $(dir $@)
	$(ARM64_CC) $(ARM64_CFLAGS) -c $< -o $@

# ARM64 kernel assembly
build/arm64/%.o: kernel/src/%.S
	@mkdir -p $(dir $@)
	$(ARM64_CC) $(ARM64_CFLAGS) -c $< -o $@

# ARM64 user libc compilation
build/arm64/user/libc/%.o: user/libc/%.c
	@mkdir -p $(dir $@)
	$(ARM64_CC) $(ARM64_USER_CFLAGS) -c $< -o $@

# ARM64 user program compilation
build/arm64/user/programs/%.o: user/programs/%.c
	@mkdir -p $(dir $@)
	$(ARM64_CC) $(ARM64_USER_CFLAGS) -c $< -o $@

build/arm64/user/tests/%.o: user/tests/%.c
	@mkdir -p $(dir $@)
	$(ARM64_CC) $(ARM64_USER_CFLAGS) -c $< -o $@

# ARM64 user program linking
build/arm64/user/%.elf: build/arm64/user/%.o $(ARM64_LIBC_C_OBJS) user/arch/arm64/linker.ld
	$(ARM64_LD) -nostdlib -static -T user/arch/arm64/linker.ld $(ARM64_LIBC_C_OBJS) $< -o $@

# ARM64 initrd
$(ARM64_INITRD): $(ARM64_USER_C_ELFS)
	@mkdir -p build/arm64/initrd_staging
	cp -f initrd/* build/arm64/initrd_staging/ 2>/dev/null || true
	@for f in $(ARM64_USER_C_ELFS); do cp -f "$$f" build/arm64/initrd_staging/; done
	COPYFILE_DISABLE=1 tar cf $@ --format ustar -C build/arm64/initrd_staging .
	rm -rf build/arm64/initrd_staging

# Convert initrd.tar to a linkable object with _initrd_start/_initrd_end symbols
build/arm64/initrd.o: $(ARM64_INITRD)
	cd build/arm64 && $(ARM64_LD) -r -b binary -o initrd.o initrd.tar

# ARM64 kernel ELF (with embedded initrd linked in)
$(ARM64_KERNEL): $(ARM64_OBJS) build/arm64/initrd.o
	$(ARM64_LD) $(ARM64_LDFLAGS) $(ARM64_OBJS) build/arm64/initrd.o -o $@

arm64: $(ARM64_KERNEL)
	@echo "ARM64 kernel built: $(ARM64_KERNEL)"

# Create ARM64 virtio-blk disk image (64MB)
arm64-disk:
	qemu-img create -f raw build/arm64/disk.img 64M

# Run ARM64 kernel in QEMU (SMP 2, virtio-mmio blk+net)
arm64-run: $(ARM64_KERNEL)
	@test -f build/arm64/disk.img || qemu-img create -f raw build/arm64/disk.img 64M
	qemu-system-aarch64 \
		-M virt \
		-cpu cortex-a57 \
		-smp 2 \
		-m 256M \
		-nographic \
		-kernel $(ARM64_KERNEL) \
		-drive file=build/arm64/disk.img,if=none,format=raw,id=disk0 \
		-device virtio-blk-device,drive=disk0 \
		-netdev user,id=net0,hostfwd=udp::9000-:9000 \
		-device virtio-net-device,netdev=net0 \
		-no-reboot

arm64-clean:
	rm -rf build/arm64

# --- Clean ---

clean:
	rm -rf build $(ISO) qemu_log.txt
