# Compile eBPF programs using clang and BPF target

CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

PROGS := file_open socket_connect exec_hash
OBJECTS := $(addsuffix .bpf.o,$(PROGS))

# If bpftool fails, never leave a poisoned empty vmlinux.h behind.
.DELETE_ON_ERROR:

all: vmlinux.h $(OBJECTS)

vmlinux.h: vmlinux_fallback.h
	@echo "Generating vmlinux.h from local kernel BTF..."
	-$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h.tmp 2>/dev/null || true
	@if [ ! -s vmlinux.h.tmp ]; then \
		echo "Local BTF extraction failed (common on WSL or custom kernels). Using bundled x86_64 vmlinux_fallback.h..."; \
		cp vmlinux_fallback.h vmlinux.h.tmp; \
	fi
	@test -s vmlinux.h.tmp || { echo "FATAL: could not obtain vmlinux.h"; rm -f vmlinux.h.tmp; exit 1; }
	@mv vmlinux.h.tmp vmlinux.h

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o vmlinux.h vmlinux.h.tmp

.PHONY: all clean
