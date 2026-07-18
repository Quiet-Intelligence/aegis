# Compile eBPF programs using clang and BPF target

CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

all: vmlinux.h file_open.bpf.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

file_open.bpf.o: file_open.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o vmlinux.h
