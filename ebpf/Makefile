# Compile eBPF programs using clang and BPF target

CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

all: vmlinux.h file_open.bpf.o

vmlinux.h:
	@echo "Attempting to generate vmlinux.h from local kernel BTF..."
	-$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null || true
	@if [ ! -s vmlinux.h ]; then \
		echo "Local BTF extraction failed (common on WSL). Downloading generic x86_64 vmlinux.h fallback..."; \
		wget -qO vmlinux.h https://raw.githubusercontent.com/libbpf/libbpf-bootstrap/master/src/vmlinux.h; \
	fi

file_open.bpf.o: file_open.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o vmlinux.h
