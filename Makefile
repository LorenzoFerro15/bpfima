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

KERNEL_VER := $(shell uname -r)
BPF_HEADERS := -I/usr/src/kernels/$(KERNEL_VER)/tools/lib/bpf -I/usr/src/kernels/$(KERNEL_VER)/tools/bpf/resolve_btfids/libbpf/include

CFLAGS := -O2 -g -target $(BPF_TARGET) -Wall -Werror $(BPF_HEADERS) -mllvm -bpf-stack-size=1024

CC ?= gcc
USER_CFLAGS := -O2 -g -Wall
LIBS := -lbpf -lelf -lz

# Build directory for all output files
BUILD_DIR := build

# eBPF objects to compile
BPF_OBJS := $(BUILD_DIR)/lsm_mmap_file.o \
            $(BUILD_DIR)/lsm_file_post_open.o \
			$(BUILD_DIR)/lsm_bprm_check_security.o

# Generic loader
LOADER := $(BUILD_DIR)/loader

# Policy initializer tool
POLICY_INIT := $(BUILD_DIR)/policy_init

all: $(BUILD_DIR) modules $(BPF_OBJS) $(LOADER) $(POLICY_INIT)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	@mkdir -p $(BUILD_DIR)
	@mv -f *.ko *.mod *.mod.c *.o Module.symvers modules.order $(BUILD_DIR)/ 2>/dev/null || true
	@mv -f src/*.o $(BUILD_DIR)/ 2>/dev/null || true
	@mv -f .*.cmd .*.o $(BUILD_DIR)/ 2>/dev/null || true
	@mv -f src/.*.cmd $(BUILD_DIR)/ 2>/dev/null || true
	@rm -rf .tmp_versions 2>/dev/null || true

# Generic loader
$(LOADER): loader.c | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -o $@ $< $(LIBS)

# Policy initializer
$(POLICY_INIT): tools/policy_init.c | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -I. -o $@ $< $(LIBS)

$(BUILD_DIR)/lsm_mmap_file.o: hooks/lsm/lsm_mmap_file.c | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/lsm_file_post_open.o: hooks/lsm/lsm_file_post_open.c | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/lsm_bprm_check_security.o: hooks/lsm/lsm_bprm_check_security.c | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf $(BUILD_DIR)
	rm -f .*.cmd .*.o 2>/dev/null || true
	rm -rf .tmp_versions 2>/dev/null || true

.PHONY: all modules clean
