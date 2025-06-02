# DNS Swiss Army Knife - Build Configuration
BINARY_NAME=systool
MAIN_PATH=./cmd/dns-tool
VERSION?=1.0.1
BUILD_TIME=$(shell go run -e "fmt.Print(time.Now().UTC().Format(\"2006-01-02_15:04:05\"))" 2>/dev/null || echo "unknown")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT) -s -w"
BUILD_FLAGS=-trimpath $(LDFLAGS)

# Output directory
DIST_DIR=dist

# Supported platforms
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all build clean test deps help install dev-deps lint fmt vet

# Default target
all: clean test build

# Build for current platform
build:
	@echo "Building $(BINARY_NAME) for current platform..."
	@if not exist $(DIST_DIR) mkdir $(DIST_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(DIST_DIR)/$(BINARY_NAME)$(if $(filter $(OS),Windows_NT),.exe,) $(MAIN_PATH)

# Build for all supported platforms
build-all: clean
	@echo "Building $(BINARY_NAME) for all platforms..."
	@if not exist $(DIST_DIR) mkdir $(DIST_DIR)
	@echo "Building linux/amd64..."
	set GOOS=linux&& set GOARCH=amd64&& $(GOBUILD) $(BUILD_FLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PATH)
	@echo "Building linux/arm64..."
	set GOOS=linux&& set GOARCH=arm64&& $(GOBUILD) $(BUILD_FLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 $(MAIN_PATH)
	@echo "Building darwin/amd64..."
	set GOOS=darwin&& set GOARCH=amd64&& $(GOBUILD) $(BUILD_FLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_PATH)
	@echo "Building darwin/arm64..."
	set GOOS=darwin&& set GOARCH=arm64&& $(GOBUILD) $(BUILD_FLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_PATH)
	@echo "Building windows/amd64..."
	set GOOS=windows&& set GOARCH=amd64&& $(GOBUILD) $(BUILD_FLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PATH)
	@echo "Building windows/arm64..."
	set GOOS=windows&& set GOARCH=arm64&& $(GOBUILD) $(BUILD_FLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-arm64.exe $(MAIN_PATH)

# Development build (no optimizations, includes debug info)
build-dev:
	@echo "Building development version..."
	$(GOBUILD) -race -o $(DIST_DIR)/$(BINARY_NAME)-dev $(MAIN_PATH)

# Install development dependencies
dev-deps:
	@echo "Installing development dependencies..."
	$(GOGET) -u golang.org/x/tools/cmd/goimports
	$(GOGET) -u github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) verify

# Install to GOPATH/bin
install: build
	@echo "Installing $(BINARY_NAME)..."
	cp $(DIST_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

# Run tests with coverage report
test-coverage: test
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Lint code
lint:
	@echo "Running linter..."
	golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...
	goimports -w .

# Vet code
vet:
	@echo "Running go vet..."
	$(GOCMD) vet ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	-if exist $(DIST_DIR) rd /s /q $(DIST_DIR)
	-if exist coverage.out del coverage.out
	-if exist coverage.html del coverage.html

# Create release archives
release: build-all
	@echo "Creating release archives..."
	@cd $(DIST_DIR) && for file in *; do \
		if [ -f "$$file" ]; then \
			if [[ "$$file" == *".exe" ]]; then \
				zip "$${file%.*}.zip" "$$file"; \
			else \
				tar -czf "$$file.tar.gz" "$$file"; \
			fi; \
		fi; \
	done

# Show available targets
help:
	@echo "Available targets:"
	@echo "  build        - Build for current platform"
	@echo "  build-all    - Build for all supported platforms"
	@echo "  build-dev    - Build development version with debug info"
	@echo "  deps         - Download dependencies"
	@echo "  dev-deps     - Install development dependencies"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  vet          - Run go vet"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install to GOPATH/bin"
	@echo "  release      - Create release archives"
	@echo "  help         - Show this help message"

# Check if tools are installed
check-tools:
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Run 'make dev-deps'" && exit 1)
	@which goimports > /dev/null || (echo "goimports not found. Run 'make dev-deps'" && exit 1)

# Run all quality checks
check: check-tools fmt vet lint test
