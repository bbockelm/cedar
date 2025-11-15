# Development Container for golang-cedar

This development container provides a complete environment for developing and testing the golang-cedar HTCondor CEDAR protocol implementation.

## What's Included

- **Go 1.23.4**: Latest stable Go version
- **HTCondor 23.x**: Full HTCondor installation for integration testing
  - `condor_master`, `condor_collector`, `condor_schedd`
  - `condor_shared_port` for shared port testing
  - Full daemon suite for comprehensive integration tests
- **Development Tools**:
  - `gopls` (Go language server)
  - `delve` (debugger)
  - `staticcheck` (linter)
  - `golint` (linter)
  - `pre-commit` (git hooks)
- **VS Code Extensions**:
  - Go extension with full tooling
  - GitHub Copilot (if enabled)
  - GitLens

## Usage

### GitHub Codespaces

1. Click the "Code" button on GitHub
2. Select "Codespaces" tab
3. Click "Create codespace on main"
4. Wait for the container to build (first time only)

### VS Code with Dev Containers

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop)
2. Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
3. Open the project in VS Code
4. Click "Reopen in Container" when prompted (or use Command Palette: "Dev Containers: Reopen in Container")

### Local Docker

```bash
# Build the container
docker build -t golang-cedar-dev .devcontainer/

# Run the container
docker run -it --rm -v $(pwd):/workspace golang-cedar-dev
```

## Running Tests

Inside the container:

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./security

# Run integration tests (requires HTCondor)
go test ./security -run Integration -v

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Building

```bash
# Build the package
go build .

# Build examples
go build ./examples/...

# Build specific example
go build ./examples/simple_startd_query.go
```

## HTCondor Testing

The container includes a full HTCondor installation. To start HTCondor for integration testing:

```bash
# HTCondor is installed but not running by default
# Integration tests will start their own mini HTCondor instances

# To manually start HTCondor (optional):
sudo condor_master

# Check status
condor_status
condor_q
```

## Pre-commit Hooks

The project uses pre-commit hooks for code quality:

```bash
# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

## Troubleshooting

### HTCondor Permission Issues

If you encounter HTCondor permission issues:

```bash
sudo chown -R condor:condor /var/lib/condor /var/log/condor /var/run/condor
```

### Go Module Issues

```bash
# Clean and re-download modules
go clean -modcache
go mod download
```

### Build Cache Issues

```bash
# Clean build cache
go clean -cache
```

## Environment Variables

The container sets:
- `GOPATH=/home/vscode/go`
- `PATH` includes Go binaries and tools
- `DEBIAN_FRONTEND=noninteractive` for package installation

## Notes

- The container runs as user `vscode` (UID 1000) for security
- HTCondor daemons run as `condor` user
- Integration tests create temporary HTCondor instances in `/tmp`
- The workspace is mounted at `/workspace`
