# Main module (now using shared components)
obj-m += bpfima.o
# List src/ object files
bpfima-y := $(patsubst $(src)/%.c, %.o, $(wildcard $(src)/src/*.c))

# Add include directory for modular headers
ccflags-y += -I$(src)/include

KBUILD_CFLAGS += -g -O2
# Use BTF from sysfs if available
KBUILD_MODPOST_WARN_MISSING_SYSCALLS := 1

# Enable BTF generation even without vmlinux in build dir
export CONFIG_DEBUG_INFO_BTF=y
export PAHOLE_FLAGS=--btf_gen_floats

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPF_TARGET := bpf
KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
KERNEL_VER := $(shell uname -r)
KERNEL_HEADERS := /usr/src/kernels/$(KERNEL_VER)
BPF_HEADERS := -I$(KERNEL_HEADERS)/tools/lib/bpf -I$(KERNEL_HEADERS)/tools/bpf/resolve_btfids/libbpf/include

PWD := $(shell pwd)

# Directory where vmlinux.h will be copied
VMLINUX_DIR := include-vmlinux
VMLINUX_H := $(VMLINUX_DIR)/vmlinux.h

# Mapping shell arch to BPF arch names
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

CFLAGS := -O2 -g -target $(BPF_TARGET) -isystem $(VMLINUX_DIR) -Wall -Werror -D__TARGET_ARCH_$(ARCH) $(BPF_HEADERS) -mllvm -bpf-stack-size=1024

CC ?= gcc
USER_CFLAGS := -O2 -g -Wall
LIBS := -lbpf -lelf -lz -lyaml -lcrypto

# Build directory for all output files
BUILD_DIR := build

# eBPF source files (auto-discover from hooks/lsm/)
BPF_SRCS := $(wildcard hooks/lsm/*.c)
BPF_OBJS := $(patsubst hooks/lsm/%.c,$(BUILD_DIR)/%.o,$(BPF_SRCS))

# Userspace tools
BPFIMA_TOOL := $(BUILD_DIR)/bpfima-tool

all: $(VMLINUX_H) $(BUILD_DIR) modules $(BPF_OBJS) $(BPFIMA_TOOL)

bpf-only: $(VMLINUX_H) $(BUILD_DIR) $(BPF_OBJS) $(BPFIMA_TOOL)

# Create the folder where vmlinux will be stored
$(VMLINUX_DIR):
	mkdir -p $(VMLINUX_DIR)

# Create vmlinux.h
$(VMLINUX_H): | $(VMLINUX_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

modules:
	make -C $(KERNEL_SRC) M=$(PWD) CC=gcc LD=ld OBJCOPY=objcopy modules
	@mkdir -p $(BUILD_DIR)
	@mv -f bpfima.ko bpfima.mod bpfima.mod.c bpfima.o Module.symvers modules.order $(BUILD_DIR)/ 2>/dev/null || true
	@mv -f src/*.o $(BUILD_DIR)/ 2>/dev/null || true
	@mv -f .*.cmd .*.o $(BUILD_DIR)/ 2>/dev/null || true
	@mv -f src/.*.cmd $(BUILD_DIR)/ 2>/dev/null || true
	@rm -rf .tmp_versions 2>/dev/null || true

# Unified management tool (replaces old loader + policy_init)
$(BPFIMA_TOOL): tools/bpfima_tool.c tools/yaml_parser.c tools/yaml_parser.h include/bpfima_policy_user.h include/bpfima_policy_defaults.h include/bpfima_kfunc_types.h | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -I. -o $@ tools/bpfima_tool.c tools/yaml_parser.c $(LIBS)

# Generic rule for compiling eBPF programs from hooks/lsm/
$(BUILD_DIR)/%.o: hooks/lsm/%.c hooks/hook_utils.h utils/utils.h utils/headers_bpf.h utils/bpf_kfunc_defs.h include/bpfima_kfunc_types.h $(VMLINUX_H) | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "Built eBPF object: $@"

clean:
	make -C $(KERNEL_SRC) M=$(PWD) clean
	rm -rf $(BUILD_DIR)
	rm -f .*.cmd .*.o 2>/dev/null || true
	rm -rf .tmp_versions 2>/dev/null || true

$(BUILD_DIR)/kfunc-buffer-test: tests/security/kfunc_buffer_test.c include/bpfima_kfunc_buffer.h include/bpfima_kfunc_types.h | $(BUILD_DIR)
	$(CC) -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Iinclude $< -o $@

test-security: $(BUILD_DIR)/kfunc-buffer-test
	./$(BUILD_DIR)/kfunc-buffer-test

$(BUILD_DIR)/security-regression.bpf.o: tests/security/security_regression.bpf.c utils/headers_bpf.h utils/utils.h utils/bpf_kfunc_defs.h include/bpfima_kfunc_types.h $(VMLINUX_H) | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/security-regression: tests/security/security_regression.c tests/kernel/check_kfunc_abi.h include/bpfima_kfunc_types.h | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -Wextra -Werror -Iinclude $< -o $@ -lbpf -lelf -lz

security-regression: $(BUILD_DIR)/security-regression $(BUILD_DIR)/security-regression.bpf.o $(BPF_OBJS)

$(BUILD_DIR)/module-interactions.bpf.o: tests/kernel/module_interactions.bpf.c tests/kernel/module_interactions.h utils/bpf_kfunc_defs.h include/bpfima_kfunc_types.h $(VMLINUX_H) | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/module-interactions: tests/kernel/module_interactions.c tests/kernel/module_interactions.h tests/kernel/check_kfunc_abi.h include/bpfima_kfunc_types.h | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -Wextra -Werror -pthread $< -o $@ -lbpf -lelf -lz -lcrypto

$(BUILD_DIR)/pinned-unload: tests/kernel/pinned_unload.c tools/bpfima_tool.c tools/yaml_parser.c tools/yaml_parser.h include/bpfima_policy_user.h include/bpfima_policy_defaults.h include/bpfima_kfunc_types.h include/bpfima_event.h | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -Werror -I. $< tools/yaml_parser.c -o $@ $(LIBS)

kernel-tests: security-regression $(BUILD_DIR)/module-interactions $(BUILD_DIR)/module-interactions.bpf.o $(BUILD_DIR)/pinned-unload

.PHONY: all modules clean bpf-only test-security security-regression kernel-tests
