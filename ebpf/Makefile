# Compile eBPF programs using clang and BPF target

CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

PROGS := file_open socket_connect exec_hash
OBJECTS := $(addsuffix .bpf.o,$(PROGS))

all: vmlinux.h $(OBJECTS)

# If bpftool fails, never leave a poisoned empty vmlinux.h behind —
# an empty header makes the next run fail with pages of __u64 errors.
.DELETE_ON_ERROR:

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h.tmp
	test -s vmlinux.h.tmp
	mv vmlinux.h.tmp vmlinux.h

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o vmlinux.h

.PHONY: all clean
