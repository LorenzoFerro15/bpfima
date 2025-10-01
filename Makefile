obj-m += bpfima.o

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

CFLAGS := -O2 -g -target $(BPF_TARGET) -Wall -Werror $(BPF_HEADERS)

CC ?= gcc
USER_CFLAGS := -O2 -g -Wall
LIBS := -lbpf -lelf -lz

all: modules kfunc_tpm.o loader_tpm $(LSM_OBJ)

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

kfunc_tpm.o: kfunc_tpm.c
	$(CLANG) $(CFLAGS) -c $< -o $@

loader_tpm: loader_tpm.c
	$(CC) $(USER_CFLAGS) -o $@ $< $(LIBS)

LSM_OBJ := lsm_file_open.o

$(LSM_OBJ): hooks/lsm/lsm_file_open.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f kfunc_tpm.o loader_tpm $(LSM_OBJ)

.PHONY: all modules clean