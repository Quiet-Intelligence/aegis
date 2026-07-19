#!/bin/bash
set -e

echo -e "\033[1;36m[+] Welcome to the Aegis Hackathon Demo!\033[0m"
echo "This script will compile Aegis and start the daemon and interactive TUI."

# Compile eBPF and binaries
echo -e "\n\033[1;34m[*] Compiling Aegis components (this might take a few seconds)...\033[0m"
make build > /dev/null

# Start aegisd in the background
echo -e "\n\033[1;34m[*] Starting Aegis Control Plane Daemon (aegisd) in the background...\033[0m"
if command -v sudo >/dev/null 2>&1; then
    sudo ./bin/aegisd &
else
    ./bin/aegisd &
fi
AEGISD_PID=$!

# Ensure it shuts down when we exit
trap 'echo -e "\n\033[1;31m[*] Shutting down aegisd...\033[0m"; if command -v sudo >/dev/null 2>&1; then sudo kill $AEGISD_PID 2>/dev/null; else kill $AEGISD_PID 2>/dev/null; fi' EXIT

# Give aegisd time to initialize eBPF probes and SQLite db
sleep 2

# Run TUI
echo -e "\033[1;34m[*] Starting Aegis Live TUI...\033[0m"
./bin/aegis-tui
