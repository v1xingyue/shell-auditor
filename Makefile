.PHONY: all build clean install test run

# Go 版本
GO_VERSION := 1.21

# 项目信息
BINARY_NAME := shell-auditor
VERSION := 1.0.0
BUILD_TIME := $(shell date +%Y-%m-%d\ %H:%M:%S)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# 构建标志
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT) -s -w"

# 目标平台
TARGET_OS := linux
TARGET_ARCH := amd64

# 安装路径
INSTALL_PREFIX := /usr/local
BIN_DIR := $(INSTALL_PREFIX)/bin
CONFIG_DIR := /etc/shell-auditor
LOG_DIR := /var/log/shell-auditor

all: build

# 生成BPF代码
generate:
	@echo "Generating BPF code..."
	cd internal/bpf && go generate ./...

# 构建
build: generate
	@echo "Building $(BINARY_NAME)..."
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/shell-auditor
	@echo "Build complete: $(BINARY_NAME)"

# 构建所有平台
build-all: generate
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 ./cmd/shell-auditor
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 ./cmd/shell-auditor
	@echo "Build complete"

# 清理
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*
	rm -f internal/bpf/bpf_*.go internal/bpf/bpf_*.o
	@echo "Clean complete"

# 安装
install: build
	@echo "Installing $(BINARY_NAME)..."
	install -d $(BIN_DIR)
	install -m 755 $(BINARY_NAME) $(BIN_DIR)/
	install -d $(CONFIG_DIR)
	install -d $(LOG_DIR)
	@echo "Installation complete"
	@echo "Binary: $(BIN_DIR)/$(BINARY_NAME)"
	@echo "Config: $(CONFIG_DIR)"
	@echo "Logs: $(LOG_DIR)"

# 卸载
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	rm -f $(BIN_DIR)/$(BINARY_NAME)
	@echo "Uninstall complete"

# 测试
test:
	@echo "Running tests..."
	go test -v ./...

# 运行
run: build
	@echo "Running $(BINARY_NAME)..."
	sudo ./$(BINARY_NAME) -shell -v

# 打包
package: build
	@echo "Creating package..."
	tar czf $(BINARY_NAME)-$(VERSION)-$(TARGET_OS)-$(TARGET_ARCH).tar.gz $(BINARY_NAME) README.md
	@echo "Package created: $(BINARY_NAME)-$(VERSION)-$(TARGET_OS)-$(TARGET_ARCH).tar.gz"

# 依赖
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# 格式化代码
fmt:
	@echo "Formatting code..."
	go fmt ./...

# 代码检查
lint:
	@echo "Running linters..."
	golangci-lint run ./...

# 帮助
help:
	@echo "Available targets:"
	@echo "  all       - Build the project (default)"
	@echo "  build     - Build the binary"
	@echo "  build-all - Build for multiple platforms"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to system"
	@echo "  uninstall - Remove from system"
	@echo "  test      - Run tests"
	@echo "  run       - Build and run"
	@echo "  package   - Create release package"
	@echo "  deps      - Download dependencies"
	@echo "  fmt       - Format code"
	@echo "  lint      - Run linters"
	@echo "  help      - Show this help"