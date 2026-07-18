# Base image: minimal Debian, standard for toolchains
FROM debian:bookworm-slim

# L0-3: Container-local ephemeral $HOME with no shell init files.
# We create a dedicated unprivileged user for the agent.
RUN useradd -m -d /home/agent -s /bin/bash agent && \
    # Remove any default skeleton files that could be used for persistence or init exploits
    rm -rf /home/agent/.* 2>/dev/null || true

# Install basic tools needed for a git + shell environment
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    bash \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# L0-1: Prepare the explicit scratch/workspace directory
RUN mkdir -p /workspace && chown agent:agent /workspace

# Set the working directory
WORKDIR /workspace

# Switch to the unprivileged user
USER agent

# Set the ephemeral home explicitly
ENV HOME=/home/agent

# Default entrypoint is a bash shell
ENTRYPOINT ["/bin/bash"]
