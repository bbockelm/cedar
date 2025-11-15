# Quick Start with GitHub Codespaces

GitHub Codespaces provides a complete development environment in your browser with HTCondor pre-installed.

## Getting Started

1. **Create a Codespace**
   - Go to the repository on GitHub
   - Click the green "Code" button
   - Select the "Codespaces" tab
   - Click "Create codespace on main"
   - Wait 2-3 minutes for the environment to build (first time only)

2. **Environment is Ready**
   Once the codespace loads, you'll have:
   - VS Code in your browser
   - Go 1.23.4 installed
   - HTCondor 23.x installed
   - All development tools ready

## Quick Commands

### Run Tests

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./security

# Run integration tests (these start HTCondor instances)
go test ./security -run Integration -v

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Build Examples

```bash
# Build all examples
go build ./examples/...

# Run a simple query example
go build -o simple_query examples/simple_startd_query.go
# (Won't connect without real HTCondor collector, but demonstrates API)
```

### Run Pre-commit Hooks

```bash
# Install hooks
pre-commit install

# Run on all files
pre-commit run --all-files
```

## Working with HTCondor

The integration tests automatically start mini HTCondor instances, so you don't need to manually start HTCondor. However, if you want to experiment:

```bash
# Check HTCondor version
condor_version

# HTCondor commands are available
condor_status --help
condor_q --help
```

## Tips

- **Terminal**: Use Ctrl+` to open/close the integrated terminal
- **Go Extension**: Hover over functions for documentation
- **Debugging**: Set breakpoints and press F5 to debug tests
- **Git**: All git operations work normally in the codespace

## Saving Your Work

- Changes are automatically saved to your GitHub account
- The codespace persists until you delete it
- You can have multiple codespaces for different branches

## Stopping/Deleting

- Close the browser tab to stop working (codespace auto-stops after inactivity)
- Go to github.com/codespaces to manage/delete codespaces
- Codespaces have usage limits depending on your GitHub plan

## Common Tasks

### Adding Dependencies

```bash
go get github.com/some/package
go mod tidy
```

### Formatting Code

```bash
# Format all Go files
gofmt -w .

# Or use goimports (better)
goimports -w .
```

### Running Linters

```bash
# Run staticcheck
staticcheck ./...

# Run golint
golint ./...
```

## Troubleshooting

### "Go tools need to be updated"
- Click "Install All" when prompted by VS Code

### Tests fail with permission errors
- Integration tests handle their own HTCondor instances
- Check logs with `-v` flag: `go test -v ./security`

### Module issues
```bash
go clean -modcache
go mod download
```

## Next Steps

- Explore the [examples/](../examples/) directory
- Read [protocol/CEDAR_PROTOCOL.md](../protocol/CEDAR_PROTOCOL.md)
- Check [security/](../security/) for authentication examples
- Review integration tests in [security/collector_integration_test.go](../security/collector_integration_test.go)
