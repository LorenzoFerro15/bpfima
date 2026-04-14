# Main module (now using shared components)
obj-m += bpfima.o
bpfima-y := src/bpfima_main.o src/hash_utils.o src/tpm_ops.o src/measurements.o src/kfuncs_container.o src/container.o src/kfuncs_measure.o src/merkle.o src/securityfs_utils.o src/policy_manager.o src/policy_namespace.o src/kfuncs_policy.o src/policy_securityfs.o

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
KERNEL_HEADERS := /usr/src/kernels/$(KERNEL_VER)
KERNEL_VER := $(shell uname -r)
BPF_HEADERS := -I$(KERNEL_HEADERS)tools/lib/bpf -I$(KERNEL_HEADERS)tools/bpf/resolve_btfids/libbpf/include

# Directory where vmlinux.h will be copied
VMLINUX_DIR := include-vmlinux
VMLINUX_H := $(VMLINUX_DIR)/vmlinux.h

# Mapping shell arch to BPF arch names
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

CFLAGS := -O2 -g -target $(BPF_TARGET) -isystem $(VMLINUX_DIR) -Wall -Werror -D__TARGET_ARCH_$(ARCH) $(BPF_HEADERS) -mllvm -bpf-stack-size=1024

CC ?= gcc
USER_CFLAGS := -O2 -g -Wall
LIBS := -lbpf -lelf -lz -lyaml

# Build directory for all output files
BUILD_DIR := build

# eBPF source files (auto-discover from hooks/lsm/)
BPF_SRCS := $(wildcard hooks/lsm/*.c)
BPF_OBJS := $(patsubst hooks/lsm/%.c,$(BUILD_DIR)/%.o,$(BPF_SRCS))

# Userspace tools
BPFIMA_TOOL := $(BUILD_DIR)/bpfima-tool

all: $(VMLINUX_H) $(BUILD_DIR) modules $(BPF_OBJS) $(BPFIMA_TOOL)

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
	@mv -f *.ko *.mod *.mod.c *.o Module.symvers modules.order $(BUILD_DIR)/ 2>/dev/null || true
	@mv -f src/*.o $(BUILD_DIR)/ 2>/dev/null || true
	@mv -f .*.cmd .*.o $(BUILD_DIR)/ 2>/dev/null || true
	@mv -f src/.*.cmd $(BUILD_DIR)/ 2>/dev/null || true
	@rm -rf .tmp_versions 2>/dev/null || true

# Unified management tool (replaces old loader + policy_init)
$(BPFIMA_TOOL): tools/bpfima_tool.c tools/yaml_parser.c | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -I. -o $@ tools/bpfima_tool.c tools/yaml_parser.c $(LIBS)

# Generic rule for compiling eBPF programs from hooks/lsm/
$(BUILD_DIR)/%.o: hooks/lsm/%.c | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "Built eBPF object: $@"

clean:
	make -C $(KERNEL_SRC) M=$(PWD) clean
	rm -rf $(BUILD_DIR)
	rm -f .*.cmd .*.o 2>/dev/null || true
	rm -rf .tmp_versions 2>/dev/null || true

.PHONY: all modules clean
