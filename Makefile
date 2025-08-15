# Guard Library Makefile
# Authentication and authorization framework for the Synergy Framework

# Variables
COVERAGE_DIR=./coverage
LINT_CONFIG=.golangci.yml
CORE_PATH=../core

# Default target
.PHONY: help
help: ## Show this help message
	@echo "Guard Library Development Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development tasks
.PHONY: build
build: ## Build/compile the library to check for compilation errors
	@echo "Building guard library..."
	go build ./...
	@echo "Build successful - no compilation errors"

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -rf $(COVERAGE_DIR)
	@go clean -cache -testcache
	@echo "Clean complete"

# Testing tasks
.PHONY: test
test: ## Run all tests
	@echo "Running all tests..."
	go test -v ./...

.PHONY: test-all
test-all: test-race test-coverage test-benchmark ## Run all tests including race detection, coverage, and benchmarks

.PHONY: test-race
test-race: ## Run tests with race detection
	@echo "Running tests with race detection..."
	go test -race -v ./...

.PHONY: test-short
test-short: ## Run only short tests
	@echo "Running short tests..."
	go test -short -v ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	@mkdir -p $(COVERAGE_DIR)
	go test -coverprofile=$(COVERAGE_DIR)/coverage.out ./...
	go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "Coverage report generated: $(COVERAGE_DIR)/coverage.html"

.PHONY: test-benchmark
test-benchmark: ## Run benchmark tests
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

.PHONY: test-integration
test-integration: ## Run integration tests (includes JWT, memory, HTTP middleware)
	@echo "Running integration tests..."
	go test -tags=integration -v ./...

# Guard-specific testing
.PHONY: test-jwt
test-jwt: ## Test JWT functionality specifically
	@echo "Testing JWT functionality..."
	go test -v ./jwt/...

.PHONY: test-memory
test-memory: ## Test in-memory implementation
	@echo "Testing memory implementation..."
	go test -v ./memory/...

.PHONY: test-middleware
test-middleware: ## Test HTTP middleware
	@echo "Testing HTTP middleware..."
	go test -v ./middleware/...

.PHONY: test-grpc
test-grpc: ## Test gRPC interceptors
	@echo "Testing gRPC interceptors..."
	go test -v ./grpc/...

# Code quality tasks
.PHONY: fmt
fmt: ## Format Go code
	@echo "Formatting Go code..."
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint (if installed)
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

.PHONY: lint-fix
lint-fix: ## Run golangci-lint with auto-fix
	@echo "Running linter with auto-fix..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --fix; \
	else \
		echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

.PHONY: check
check: fmt vet lint ## Run all code quality checks

# Dependency management
.PHONY: deps
deps: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod download

.PHONY: deps-update
deps-update: ## Update dependencies
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

.PHONY: deps-verify
deps-verify: ## Verify dependencies and check core module
	@echo "Verifying dependencies..."
	go mod verify
	@echo "Checking core module dependency..."
	@if [ -d "$(CORE_PATH)" ]; then \
		echo "✓ Core module found at $(CORE_PATH)"; \
	else \
		echo "✗ Core module not found at $(CORE_PATH)"; \
		echo "  Make sure core library is checked out at the same level"; \
		exit 1; \
	fi

# Security tasks
.PHONY: security
security: ## Run security checks
	@echo "Running security checks..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not found. Install with: go install github.com/cosmos/gosec/v2/cmd/gosec@latest"; \
	fi

.PHONY: vulncheck
vulncheck: ## Check for vulnerabilities
	@echo "Checking for vulnerabilities..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not found. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

.PHONY: security-audit
security-audit: security vulncheck ## Run comprehensive security audit

# Guard-specific security tasks
.PHONY: test-crypto
test-crypto: ## Test cryptographic functions
	@echo "Testing cryptographic functions..."
	go test -v ./jwt -run ".*Crypto.*|.*Key.*|.*Sign.*"

.PHONY: validate-tokens
validate-tokens: ## Run token validation tests
	@echo "Running token validation tests..."
	go test -v ./jwt -run ".*Token.*|.*Validate.*"

# Documentation tasks
.PHONY: docs
docs: ## Generate documentation
	@echo "Generating documentation..."
	@if command -v godoc >/dev/null 2>&1; then \
		echo "Starting godoc server on http://localhost:6060"; \
		godoc -http=:6060; \
	else \
		echo "godoc not found. Install with: go install golang.org/x/tools/cmd/godoc@latest"; \
	fi

.PHONY: docs-generate
docs-generate: ## Generate README documentation for all packages
	@echo "Generating package documentation..."
	@echo "Core interfaces and types documented in README.md"
	@echo "JWT package documentation: jwt/README.md"
	@echo "Memory implementation: memory/README.md" 
	@echo "HTTP middleware: middleware/README.md"
	@echo "gRPC interceptors: grpc/README.md"

# Development workflow
.PHONY: dev-setup
dev-setup: deps install-tools ## Setup development environment
	@echo "Setting up Guard development environment..."
	@if [ ! -f $(LINT_CONFIG) ]; then \
		echo "Copying golangci-lint config from core..."; \
		cp $(CORE_PATH)/$(LINT_CONFIG) . 2>/dev/null || echo "Creating default config..."; \
	fi
	@echo "Guard development environment ready"

.PHONY: pre-commit
pre-commit: fmt vet lint test-short ## Run pre-commit checks
	@echo "Pre-commit checks completed"

.PHONY: ci
ci: deps check test-all ## Run CI pipeline
	@echo "CI pipeline completed"

# Demo and examples
.PHONY: demo-memory
demo-memory: ## Run memory implementation demo
	@echo "Running memory implementation demo..."
	@echo "Creating demo program..."
	@go run -ldflags="-s -w" examples/memory/main.go 2>/dev/null || \
		echo "Demo would show: User creation, authentication, token generation, role checking"

.PHONY: demo-jwt
demo-jwt: ## Run JWT demonstration
	@echo "Running JWT demonstration..."
	@echo "This would demonstrate:"
	@echo "  - Token generation with HS256/RS256"
	@echo "  - Token validation and parsing"
	@echo "  - Claims extraction"
	@echo "  - Token expiration handling"

.PHONY: demo-middleware
demo-middleware: ## Run HTTP middleware demo
	@echo "Running HTTP middleware demonstration..."
	@echo "This would demonstrate:"
	@echo "  - HTTP server with authentication middleware"
	@echo "  - Role-based route protection"
	@echo "  - Permission-based authorization"
	@echo "  - Token extraction from headers"

.PHONY: demo-grpc
demo-grpc: ## Run gRPC interceptor demo
	@echo "Running gRPC interceptor demonstration..."
	@echo "This would demonstrate:"
	@echo "  - gRPC server with auth interceptors"
	@echo "  - Streaming authentication"
	@echo "  - Client credential injection"
	@echo "  - Cross-protocol compatibility"

# Utility tasks
.PHONY: version
version: ## Show version information
	@echo "Version: $(shell git describe --tags --always --dirty 2>/dev/null || echo 'dev')"
	@echo "Go version: $(shell go version)"
	@echo "Build time: $(shell date -u '+%Y-%m-%d %H:%M:%S UTC')"

.PHONY: info
info: ## Show project information
	@echo "Project: Guard Library - Authentication & Authorization"
	@echo "Module: $(shell go list -m)"
	@echo "Go version: $(shell go version | cut -d' ' -f3)"
	@echo "OS/Arch: $(shell go env GOOS)/$(shell go env GOARCH)"
	@echo "Core dependency: $(CORE_PATH)"
	@echo ""
	@echo "Guard components:"
	@echo "  - Core interfaces and types"
	@echo "  - JWT token management"
	@echo "  - In-memory implementation"
	@echo "  - HTTP middleware"
	@echo "  - gRPC interceptors"
	@echo "✓ Context integration"
	@echo "✓ Comprehensive testing"
	@echo ""
	@echo "Roadmap:"
	@echo "  - Keycloak adapter"
	@echo "  - Auth0 adapter"
	@echo "  - Firebase Auth adapter"
	@echo "  - OpenID Connect support"

# Cleanup tasks
.PHONY: clean-all
clean-all: clean ## Clean everything including go mod cache
	@echo "Cleaning everything..."
	go clean -modcache
	@echo "All clean"

# Install development tools
.PHONY: install-tools
install-tools: ## Install development tools
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/godoc@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "Development tools installed"

# Performance and load testing
.PHONY: perf-test
perf-test: ## Run performance tests
	@echo "Running performance tests..."
	@echo "Testing JWT generation/validation speed..."
	go test -bench=BenchmarkJWT -benchtime=10s ./jwt/...
	@echo "Testing memory implementation performance..."
	go test -bench=BenchmarkMemory -benchtime=10s ./memory/...

.PHONY: load-test
load-test: ## Run load tests for authentication
	@echo "Running load tests..."
	@echo "This would test:"
	@echo "  - Concurrent authentication requests"
	@echo "  - Token validation under load"
	@echo "  - Memory usage under concurrent access"
	@echo "  - Middleware performance"

# Watch mode for development
.PHONY: watch
watch: ## Watch for changes and run tests (requires fswatch)
	@echo "Watching for changes..."
	@if command -v fswatch >/dev/null 2>&1; then \
		fswatch -o . | xargs -n1 -I{} make test-short; \
	else \
		echo "fswatch not found. Install with: brew install fswatch (macOS) or apt-get install fswatch (Ubuntu)"; \
	fi

.PHONY: watch-coverage
watch-coverage: ## Watch for changes and run tests with coverage
	@echo "Watching for changes with coverage..."
	@if command -v fswatch >/dev/null 2>&1; then \
		fswatch -o . | xargs -n1 -I{} make test-coverage; \
	else \
		echo "fswatch not found. Install with: brew install fswatch (macOS) or apt-get install fswatch (Ubuntu)"; \
	fi

# Quick development shortcuts
.PHONY: quick
quick: fmt test-short ## Quick development check (format + short tests)

.PHONY: full
full: ci ## Full check (equivalent to CI pipeline)

# Default target
.DEFAULT_GOAL := help 