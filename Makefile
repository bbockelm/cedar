.PHONY: help docker-build docker-test docker-test-unit docker-test-integration docker-test-coverage docker-shell clean

# Default target
help:
	@echo "golang-cedar Docker targets:"
	@echo "  docker-build              - Build the Docker test image"
	@echo "  docker-test               - Run all tests in Docker"
	@echo "  docker-test-unit          - Run unit tests only (skip integration)"
	@echo "  docker-test-integration   - Run integration tests only"
	@echo "  docker-test-coverage      - Run tests with coverage report"
	@echo "  docker-shell              - Start interactive shell in Docker"
	@echo "  docker-compose-test       - Run tests using docker-compose"
	@echo "  clean                     - Clean up Docker images and volumes"

# Build the Docker image
docker-build:
	docker build -t golang-cedar-test .

# Run all tests
docker-test: docker-build
	docker run --rm golang-cedar-test

# Run unit tests only
docker-test-unit: docker-build
	docker run --rm golang-cedar-test go test -v -short ./...

# Run integration tests
docker-test-integration: docker-build
	docker run --rm --privileged golang-cedar-test go test -v ./security -run Integration

# Run with coverage
docker-test-coverage: docker-build
	docker run --rm golang-cedar-test sh -c "go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out"

# Interactive shell
docker-shell: docker-build
	docker run -it --rm -v $(PWD):/app golang-cedar-test /bin/bash

# Docker Compose targets
docker-compose-test:
	docker-compose up --abort-on-container-exit test

docker-compose-test-unit:
	docker-compose up --abort-on-container-exit test-unit

docker-compose-test-integration:
	docker-compose up --abort-on-container-exit test-integration

docker-compose-coverage:
	docker-compose up --abort-on-container-exit test-coverage

# Clean up
clean:
	docker rmi golang-cedar-test 2>/dev/null || true
	docker-compose down -v 2>/dev/null || true
	docker volume prune -f
