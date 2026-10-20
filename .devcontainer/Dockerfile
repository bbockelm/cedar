# Dockerfile for golang-cedar development and testing
# Using AlmaLinux 9 (RHEL 9 variant) as base because HTCondor doesn't have ARM builds for Ubuntu
FROM almalinux:9

# Enable EPEL repository for missing HTCondor dependencies
RUN dnf install -y epel-release && dnf clean all

# Install basic dependencies
RUN dnf install -y --allowerasing \
    curl \
    git \
    wget \
    gnupg2 \
    ca-certificates \
    tar \
    gzip \
    && dnf clean all

# Install Go: the newest stable patch of the minor in GO_MINOR, the same
# version CI's setup-go resolves for '1.27'. Pass GO_VERSION to pin an exact
# release instead.
ARG GO_MINOR=1.27
ARG GO_VERSION=
ARG TARGETARCH=amd64
RUN set -eu; \
    if [ -z "$GO_VERSION" ]; then \
        GO_MINOR_RE=$(printf '%s' "$GO_MINOR" | sed 's/\./\\./g'); \
        GO_VERSION=$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all' | \
            grep -oE "\"go${GO_MINOR_RE}(\\.[0-9]+)?\"" | tr -d '"' | sed 's/^go//' | sort -V | tail -n 1); \
    fi; \
    test -n "$GO_VERSION"; \
    echo "Installing Go ${GO_VERSION}"; \
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz; \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-${TARGETARCH}.tar.gz; \
    rm go${GO_VERSION}.linux-${TARGETARCH}.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install HTCondor
# HTCondor supports EL9 (Enterprise Linux 9) with ARM builds
RUN curl -fsSL https://research.cs.wisc.edu/htcondor/repo/keys/HTCondor-23.x-Key -o /tmp/condor-key \
    && rpm --import /tmp/condor-key \
    && rm /tmp/condor-key \
    && cat > /etc/yum.repos.d/htcondor.repo <<EOF
[htcondor-stable]
name=HTCondor Stable RPM Repository
baseurl=https://htcss-downloads.chtc.wisc.edu/repo/23.x/el9/\$basearch/release
enabled=1
gpgcheck=1
gpgkey=https://research.cs.wisc.edu/htcondor/repo/keys/HTCondor-23.x-Key
EOF
RUN dnf install -y htcondor && dnf clean all

# Install development tools
RUN dnf install -y \
    gcc \
    gcc-c++ \
    make \
    vim \
    nano \
    sqlite \
    less \
    && dnf clean all

# Install Go development tools
RUN go install golang.org/x/tools/gopls@latest \
    && go install github.com/go-delve/delve/cmd/dlv@latest \
    && go install honnef.co/go/tools/cmd/staticcheck@latest \
    && go install golang.org/x/lint/golint@latest

# Install pre-commit
RUN dnf install -y \
    python3 \
    python3-pip \
    && pip3 install pre-commit \
    && dnf clean all

# Create a non-root user for development
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && dnf install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && dnf clean all

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
