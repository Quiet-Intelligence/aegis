#!/bin/bash
# Install Aegis core dependencies. Supports apt (Debian/Ubuntu/WSL) and
# pacman (Arch). Kernel headers are best-effort: they do not exist for
# WSL or some custom kernels, and that is fine because vmlinux.h comes
# from live BTF (or the download fallback).
set -u

echo "Installing Aegis core dependencies..."

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y clang llvm libbpf-dev make golang wget
    sudo apt-get install -y "linux-headers-$(uname -r)" bpftool 2>/dev/null \
        || echo "Note: linux-headers/bpftool not available for this kernel (expected on WSL/custom). Continuing."
elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --needed --noconfirm clang libbpf make go wget bpf
else
    echo "No supported package manager found (need apt-get or pacman)."
    echo "Install manually: clang, libbpf headers, make, go, wget, bpftool."
    exit 1
fi

echo "Dependencies installed successfully."
