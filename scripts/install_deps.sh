#!/bin/bash
echo "Installing Aegis core dependencies..."
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev make golang
sudo apt-get install -y linux-headers-$(uname -r) || echo "Warning: Could not install linux-headers (expected on WSL/custom kernels). Aegis will fallback to packaged vmlinux.h."
echo "Dependencies installed successfully."
