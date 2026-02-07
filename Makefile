APP_NAME := wg-busy
BUILD_DIR := bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build run dev clean test lint fmt tidy docker-build docker-run help

all: build

build: ## Build the Go binary
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) .

run: build ## Build and run locally
	$(BUILD_DIR)/$(APP_NAME) -listen :8080 -config ./data/config.yaml -wg-config ./data/wg0.conf

dev: ## Run with go run for fast iteration
	go run . -listen :8080 -config ./data/config.yaml -wg-config ./data/wg0.conf

test: ## Run all tests
	go test -v -race -count=1 ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

fmt: ## Format Go source files
	gofmt -s -w .
	goimports -w .

tidy: ## Tidy go modules
	go mod tidy

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)

docker-build: ## Build Docker image
	docker build -t $(APP_NAME):$(VERSION) -t $(APP_NAME):latest .

docker-run: docker-build ## Build and run in Docker with WireGuard capabilities
	docker run --rm -it \
		--cap-add NET_ADMIN \
		--cap-add SYS_MODULE \
		--sysctl net.ipv4.ip_forward=1 \
		--sysctl net.ipv4.conf.all.src_valid_mark=1 \
		-p 8080:8080 \
		-p 51820:51820/udp \
		-v $(PWD)/data:/app/data \
		$(APP_NAME):latest

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
