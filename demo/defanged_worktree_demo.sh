#!/bin/bash
# DEFANGED PATTERN FOR A SECURITY DEMO, NOT A WORKING EXPLOIT
# This script simulates the sequence of git worktree commands
# that lead to the CVE-2026-55607 worktree-naming confusion pattern,
# specifically designed to trigger Aegis anomaly scoring.
# IT DOES NOT INSTALL OR EXECUTE A PAYLOAD.

set -e

echo "[*] Setting up mock repo..."
mkdir -p /workspace/demo-repo
cd /workspace/demo-repo
git init

# Step 1: Worktree confusion simulation
echo "[*] Creating confusing worktree named '.git'"
mkdir -p /workspace/.claude/worktrees
git worktree add /workspace/.claude/worktrees/.git

# Step 2: Enter/exit loop to trigger scorer anomaly (repetitive worktree cycles)
echo "[*] Triggering repetitive file access anomaly (simulating git fsmonitor bypass)..."
for i in {1..15}; do
    cd /workspace/.claude/worktrees/.git
    git status > /dev/null
    cd /workspace/demo-repo
done

# Step 3: Write harmless marker file to trigger file_open outside expected prefix
echo "[*] Writing harmless marker to /tmp (simulating unsandboxed write)"
echo "marker" > /tmp/aegis_marker.txt

echo "[*] Defanged demo sequence complete. Aegis should have flagged this session."
