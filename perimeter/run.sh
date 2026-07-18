#!/bin/bash
set -eo pipefail

# L0-1 to L0-7 Configuration Script
# This script wraps the docker run command to enforce all Layer 0 constraints.

IMAGE_NAME="aegis-agent"
WORKSPACE_DIR="$(pwd)/test_workspace"
ALLOWLIST_IPS=${EGRESS_ALLOWLIST:-"8.8.8.8,1.1.1.1"} # Comma separated IPs for network egress

echo "Building Aegis Perimeter container..."
docker build -t "$IMAGE_NAME" .

echo "Preparing explicit workspace (L0-1)..."
mkdir -p "$WORKSPACE_DIR"

# L0-7 Note: User namespace remapping must be enabled in /etc/docker/daemon.json
# via { "userns-remap": "default" } prior to running this script to fully satisfy L0-7.

# L0-6 Note: Outbound network egress allowlist requires host-level iptables or
# an egress proxy. For demonstration, we use Docker's bridge network which can
# be firewalled using iptables DOCKER-USER chain on the host.

echo "Running container with enforced static perimeter..."
docker run -it --rm \
    --name aegis-agent-runtime \
    `# L0-1: Read-only root filesystem` \
    --read-only \
    `# L0-1: Only explicit scratch directory is writable` \
    -v "${WORKSPACE_DIR}:/workspace:rw" \
    `# L0-2: Explicitly NO bind mounts of host credential paths (e.g., ~/.ssh) are provided here.` \
    `# L0-3: Container-local ephemeral $HOME is handled by the Dockerfile.` \
    --tmpfs /tmp \
    --tmpfs /run \
    --tmpfs /home/agent \
    `# L0-4: Drop all capabilities, add back only if absolutely necessary` \
    --cap-drop=ALL \
    `# L0-5: Apply seccomp profile to deny ptrace, mount, unshare, etc.` \
    --security-opt seccomp=seccomp-profile.json \
    "$IMAGE_NAME"
