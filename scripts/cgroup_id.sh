#!/bin/bash
# Prints the cgroup v2 ID (kernfs inode number) for a running Docker container.
# This is the value bpf_get_current_cgroup_id() reports, i.e. what you should
# export as AEGIS_CGROUP_ID to scope aegisd to that container.
#
# Usage: ./scripts/cgroup_id.sh <container-name-or-id>
set -euo pipefail

NAME="${1:?usage: cgroup_id.sh <container-name-or-id>}"

CID="$(docker inspect -f '{{.Id}}' "$NAME" 2>/dev/null)" || {
    echo "error: container '$NAME' not found or docker unreachable" >&2
    exit 1
}

# cgroup v2 paths differ by docker cgroup driver (systemd vs cgroupfs).
CANDIDATES=(
    "/sys/fs/cgroup/system.slice/docker-${CID}.scope"
    "/sys/fs/cgroup/docker/${CID}"
    "/sys/fs/cgroup/system.slice/containerd-${CID}.scope"
)

for p in "${CANDIDATES[@]}"; do
    if [ -d "$p" ]; then
        stat -c %i "$p"
        exit 0
    fi
done

echo "error: cgroup directory not found for container $NAME ($CID)." >&2
echo "looked in:" >&2
printf '  %s\n' "${CANDIDATES[@]}" >&2
echo "hint: find it manually with: docker inspect -f '{{.State.Pid}}' $NAME | xargs -I{} cat /proc/{}/cgroup" >&2
exit 1
