.PHONY: all build build-linux build-windows build-all test test-go test-py run clean

BIN_DIR := bin
APP_NAME := chameleon

all: build-all test

build:
	@mkdir -p $(BIN_DIR)
	@echo "Building local binary..."
	go build -ldflags="-s -w" -o $(BIN_DIR)/$(APP_NAME) ./cmd/chameleon

build-linux:
	@mkdir -p $(BIN_DIR)
	@echo "Cross-compiling standalone Linux binary (amd64)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN_DIR)/$(APP_NAME)-linux-amd64 ./cmd/chameleon
	@cp $(BIN_DIR)/$(APP_NAME)-linux-amd64 $(BIN_DIR)/$(APP_NAME)

build-windows:
	@mkdir -p $(BIN_DIR)
	@echo "Cross-compiling standalone Windows executable (amd64)..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN_DIR)/$(APP_NAME)-windows-amd64.exe ./cmd/chameleon
	@cp $(BIN_DIR)/$(APP_NAME)-windows-amd64.exe ./$(APP_NAME).exe

build-all: build-linux build-windows
	@echo "Multi-platform standalone binaries ready in $(BIN_DIR)/"

test: test-go test-py

test-go:
	@echo "Running Go test suite..."
	go test -v -race ./test/...

test-py:
	@echo "Running Python Intelligence test suite..."
	python3 -m unittest discover -s python_intel/tests

run: build
	@echo "Starting Chameleon Honeypot..."
	./$(BIN_DIR)/$(APP_NAME) -c config/config.json

clean:
	@echo "Cleaning artifacts..."
	rm -rf $(BIN_DIR) $(APP_NAME).exe logs/sessions/* logs/*.log logs/*.jsonl logs/*.cef
