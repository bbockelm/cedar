# Dockerfile for testing golang-cedar package
# This can be used for CI/CD or standalone testing
# Using AlmaLinux 9 (RHEL 9 variant) as base because HTCondor doesn't have ARM builds for Ubuntu
FROM almalinux:9

# Install dependencies
RUN dnf install -y --allowerasing \
    curl \
    git \
    wget \
    gnupg2 \
    ca-certificates \
    tar \
    gzip \
    && dnf clean all

# Install Go (supports multiple architectures including ARM)
ARG GO_VERSION=1.23.4
ARG TARGETARCH=amd64
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-${TARGETARCH}.tar.gz \
    && rm go${GO_VERSION}.linux-${TARGETARCH}.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

# Install HTCondor for integration tests
# HTCondor supports EL9 (Enterprise Linux 9) with ARM builds
RUN curl -fsSL https://research.cs.wisc.edu/htcondor/repo/keys/HTCondor-25.x-Key -o /tmp/condor-key \
    && rpm --import /tmp/condor-key \
    && rm /tmp/condor-key \
    && cat > /etc/yum.repos.d/htcondor.repo <<EOF
[htcondor-stable]
name=HTCondor Stable RPM Repository
baseurl=https://research.cs.wisc.edu/htcondor/repo/25.x/el9/\$basearch
enabled=1
gpgcheck=1
gpgkey=https://research.cs.wisc.edu/htcondor/repo/keys/HTCondor-25.x-Key
EOF
RUN dnf install -y condor && dnf clean all

# Set up HTCondor directories
RUN mkdir -p /var/lib/condor /var/log/condor /var/run/condor /var/lock/condor \
    && chown -R condor:condor /var/lib/condor /var/log/condor /var/run/condor /var/lock/condor

# Create runner user for running tests (tests cannot run as root)
RUN useradd -m -s /bin/bash runner \
    && mkdir -p /home/runner/go \
    && chown -R runner:runner /home/runner

# Set up Go environment for runner user
ENV GOPATH="/home/runner/go"
ENV PATH="${GOPATH}/bin:${PATH}"

WORKDIR /app

# Copy go module files
COPY go.mod go.sum ./

# Download dependencies as root (for caching)
RUN go mod download

# Copy source code
COPY . .

# Change ownership of the app directory to runner user
RUN chown -R runner:runner /app

# Switch to runner user for running tests
USER runner

# Run tests by default
CMD ["go", "test", "-v", "./..."]
