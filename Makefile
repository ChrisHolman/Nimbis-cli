.PHONY: build install clean test run help

BINARY_NAME=nimbis
VERSION=0.1.0
BUILD_DIR=build

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary for current platform
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) .
	@echo "Build complete: ./$(BINARY_NAME)"

build-all: ## Build for all platforms
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Build complete. Binaries in $(BUILD_DIR)/"

install: build ## Install to /usr/local/bin (requires sudo)
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BINARY_NAME) /usr/local/bin/
	@echo "Installation complete. Run '$(BINARY_NAME) --help'"

clean: ## Clean build artifacts
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)
	@echo "Clean complete"

test: ## Run tests
	@echo "Running tests..."
	$(GOTEST) -v ./...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "Dependencies downloaded"

run: ## Run the application
	$(GOBUILD) -o $(BINARY_NAME) .
	./$(BINARY_NAME)

run-all: ## Run all scan types on current directory
	$(GOBUILD) -o $(BINARY_NAME) .
	./$(BINARY_NAME) --all -v

run-iac: ## Run IaC scan only
	$(GOBUILD) -o $(BINARY_NAME) .
	./$(BINARY_NAME) --iac -v

run-secrets: ## Run secrets scan only
	$(GOBUILD) -o $(BINARY_NAME) .
	./$(BINARY_NAME) --secrets -v

lint: ## Run linter
	@echo "Running linter..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "Installing golangci-lint..."; go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; }
	golangci-lint run ./...

fmt: ## Format code
	@echo "Formatting code..."
	gofmt -w .
	@echo "Formatting complete"

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .
	docker tag $(BINARY_NAME):$(VERSION) $(BINARY_NAME):latest
	@echo "Docker image built: $(BINARY_NAME):$(VERSION)"

release: clean test build-all ## Create a release build
	@echo "Creating release $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/release
	cd $(BUILD_DIR) && \
	tar -czf release/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64 && \
	tar -czf release/$(BINARY_NAME)-$(VERSION)-linux-arm64.tar.gz $(BINARY_NAME)-linux-arm64 && \
	tar -czf release/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64 && \
	tar -czf release/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64 && \
	zip -q release/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe
	@echo "Release packages created in $(BUILD_DIR)/release/"

install-tools: ## Install required scanning tools (macOS only)
	@echo "Installing scanning tools via Homebrew..."
	@command -v brew >/dev/null 2>&1 || { echo "Homebrew not found. Please install from https://brew.sh"; exit 1; }
	brew install trivy trufflehog grype syft
	pip3 install checkov
	@echo "Tools installed successfully"

check-tools: ## Check which scanning tools are available
	@echo "Checking for available scanning tools..."
	@command -v trivy >/dev/null 2>&1 && echo "✓ Trivy installed" || echo "✗ Trivy not found"
	@command -v checkov >/dev/null 2>&1 && echo "✓ Checkov installed" || echo "✗ Checkov not found"
	@command -v trufflehog >/dev/null 2>&1 && echo "✓ TruffleHog installed" || echo "✗ TruffleHog not found"
	@command -v opengrep >/dev/null 2>&1 && echo "✓ OpenGrep installed" || echo "✗ OpenGrep not found"
	@command -v grype >/dev/null 2>&1 && echo "✓ Grype installed" || echo "✗ Grype not found"
	@command -v syft >/dev/null 2>&1 && echo "✓ Syft installed" || echo "✗ Syft not found"
