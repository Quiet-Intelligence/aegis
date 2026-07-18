#!/bin/bash
set -eo pipefail

# L0-1 to L0-7 Configuration Script
# This script wraps the docker run command to enforce all Layer 0 constraints.

IMAGE_NAME="aegis-agent"
WORKSPACE_DIR="$(pwd)/test_workspace"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GATE_DIR="${AEGIS_GATE_DIR:-$PROJECT_ROOT/.aegis-run}"
NETWORK_MODE=${AEGIS_NETWORK_MODE:-none}

echo "Building Aegis Perimeter container..."
docker build -t "$IMAGE_NAME" .

echo "Preparing explicit workspace (L0-1)..."
mkdir -p "$WORKSPACE_DIR"
mkdir -p "$GATE_DIR"

echo "Exec gate directory: $GATE_DIR"
echo "The shell will wait in the kernel until aegisd starts and approves /bin/bash."
echo ""
echo "NEXT STEP (leave this terminal open):"
echo "  Open a second terminal and run:"
echo "  cd $PROJECT_ROOT && sudo ./bin/aegisd"
echo ""

# L0-7 Note: User namespace remapping must be enabled in /etc/docker/daemon.json
# via { "userns-remap": "default" } prior to running this script to fully satisfy L0-7.

# L0-6 Note: Outbound network egress allowlist requires host-level iptables or
# an egress proxy. For demonstration, we use Docker's bridge network which can
# be firewalled using iptables DOCKER-USER chain on the host.

echo "Running container with enforced static perimeter..."
echo "Network mode: $NETWORK_MODE (default none; set AEGIS_NETWORK_MODE=bridge to opt in)"
docker run -it --rm \
    --name aegis-agent-runtime \
	--network "$NETWORK_MODE" \
    `# L0-1: Read-only root filesystem` \
    --read-only \
    `# L0-1: Only explicit scratch directory is writable` \
    -v "${WORKSPACE_DIR}:/workspace:rw" \
    `# L0-2: Explicitly NO bind mounts of host credential paths (e.g., ~/.ssh) are provided here.` \
	`# L0-3: No writable home/tmp/run. /workspace is the only writable storage.` \
	`# Synchronous exec-gate socket directory (aegisd writes the socket)` \
	-v "${GATE_DIR}:/run/aegis:ro" \
    `# L0-4: Drop all capabilities, add back only if absolutely necessary` \
    --cap-drop=ALL \
    `# L0-5: Apply seccomp profile to deny ptrace, mount, unshare, etc.` \
    --security-opt seccomp=seccomp-profile.json \
    "$IMAGE_NAME"
