.PHONY: build test clean release install

BINARY_NAME=lfimap
BUILD_DIR=bin
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/lfimap

test:
	go test -v -race ./...

test-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

release:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/lfimap
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/lfimap
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/lfimap
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/lfimap
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/lfimap

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...
	goimports -w .

tidy:
	go mod tidy

run: build
	./$(BUILD_DIR)/$(BINARY_NAME) $(ARGS)

help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  clean          - Remove build artifacts"
	@echo "  install        - Install to GOPATH/bin"
	@echo "  release        - Build for multiple platforms"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo "  tidy           - Tidy go modules"
	@echo "  run ARGS=...   - Build and run with arguments"
