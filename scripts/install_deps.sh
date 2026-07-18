#!/bin/bash
echo "Installing Aegis core dependencies..."
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) make golang
echo "Dependencies installed successfully."
