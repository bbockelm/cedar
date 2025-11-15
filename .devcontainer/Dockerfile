# Dockerfile for golang-cedar development and testing
FROM ubuntu:22.04

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install basic dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    wget \
    gnupg \
    software-properties-common \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.21+
ARG GO_VERSION=1.23.4
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install HTCondor
# Add HTCondor repository
RUN wget -qO - https://research.cs.wisc.edu/htcondor/repo/keys/HTCondor-23.x-Key | apt-key add - \
    && echo "deb [arch=amd64] https://research.cs.wisc.edu/htcondor/repo/ubuntu/23.x jammy main" > /etc/apt/sources.list.d/htcondor.list

# Install HTCondor packages needed for development and testing
RUN apt-get update && apt-get install -y \
    htcondor \
    && rm -rf /var/lib/apt/lists/*

# Install development tools
RUN apt-get update && apt-get install -y \
    build-essential \
    vim \
    nano \
    less \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install Go development tools
RUN go install golang.org/x/tools/gopls@latest \
    && go install github.com/go-delve/delve/cmd/dlv@latest \
    && go install honnef.co/go/tools/cmd/staticcheck@latest \
    && go install golang.org/x/lint/golint@latest

# Install pre-commit
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && pip3 install pre-commit \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for development
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && rm -rf /var/lib/apt/lists/*

# Set up HTCondor directories with proper permissions
RUN mkdir -p /var/lib/condor /var/log/condor /var/run/condor /var/lock/condor \
    && chown -R condor:condor /var/lib/condor /var/log/condor /var/run/condor /var/lock/condor

# Create workspace directory
RUN mkdir -p /workspace && chown -R $USERNAME:$USERNAME /workspace

USER $USERNAME
WORKDIR /workspace

# Set up Go environment for the non-root user
ENV GOPATH="/home/${USERNAME}/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Verify installations
RUN go version \
    && condor_version

CMD ["/bin/bash"]
