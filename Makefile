obj-m += hello.o  

KBUILD_CFLAGS += -g -O2

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPF_TARGET := bpf

KERNEL_VER := $(shell uname -r)
BPF_HEADERS := -I/usr/src/kernels/$(KERNEL_VER)/tools/lib/bpf -I/usr/src/kernels/$(KERNEL_VER)/tools/bpf/resolve_btfids/libbpf/include

CFLAGS := -O2 -g -target $(BPF_TARGET) -Wall -Werror $(BPF_HEADERS)

CC ?= gcc
USER_CFLAGS := -O2 -g -Wall
LIBS := -lbpf -lelf -lz

all: modules kfunc.o loader

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

kfunc.o: kfunc.c
	$(CLANG) $(CFLAGS) -c $< -o $@

loader: loader.c
	$(CC) $(USER_CFLAGS) -o $@ $< $(LIBS)

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f kfunc.o loader
