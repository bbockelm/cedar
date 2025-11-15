# Dockerfile for testing golang-cedar package
# This can be used for CI/CD or standalone testing
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    wget \
    lsb-release \
    gnupg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go
ARG GO_VERSION=1.23.4
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

# Install HTCondor for integration tests
RUN wget -qO - https://research.cs.wisc.edu/htcondor/repo/keys/HTCondor-25.x-Key | apt-key add - \
    && echo "deb [arch=amd64] https://research.cs.wisc.edu/htcondor/repo/ubuntu/25.x $(lsb_release -cs) main" > /etc/apt/sources.list.d/htcondor.list \
    && apt-get update \
    && apt-get install -y condor \
    && rm -rf /var/lib/apt/lists/*

# Set up HTCondor directories
RUN mkdir -p /var/lib/condor /var/log/condor /var/run/condor /var/lock/condor \
    && chown -R condor:condor /var/lib/condor /var/log/condor /var/run/condor /var/lock/condor

WORKDIR /app

# Copy go module files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Run tests by default
CMD ["go", "test", "-v", "./..."]
