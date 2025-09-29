obj-m += hello.o

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

all: modules kfunc.o loader kfunc_simple.o loader_simple kfunc_tpm.o kfunc_tpm_sim.o loader_tpm

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

kfunc.o: kfunc.c
	$(CLANG) $(CFLAGS) -c $< -o $@

kfunc_simple.o: kfunc_simple.c
	$(CLANG) -O2 -target bpf -c $< -o $@

kfunc_tpm.o: kfunc_tpm.c
	$(CLANG) $(CFLAGS) -c $< -o $@

kfunc_tpm_sim.o: kfunc_tpm_sim.c
	$(CLANG) -O2 -target bpf -c $< -o $@

loader: loader.c
	$(CC) $(USER_CFLAGS) -o $@ $< $(LIBS)

loader_simple: loader_simple.c
	$(CC) $(USER_CFLAGS) -o $@ $< $(LIBS)

loader_tpm: loader_tpm.c
	$(CC) $(USER_CFLAGS) -o $@ $< $(LIBS)


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f kfunc.o kfunc_simple.o kfunc_tpm.o kfunc_tpm_sim.o loader loader_simple loader_tpm

test_simple: kfunc_simple.o loader_simple
	chmod +x test_simple.sh

.PHONY: all modules clean test_simple