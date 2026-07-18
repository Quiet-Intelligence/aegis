.PHONY: all ebpf daemon cli build clean run test eval

# Define paths and variables
EBPF_DIR = ebpf
CMD_DIR = cmd
BIN_DIR = bin

all: build

ebpf:
	@echo "==> Compiling eBPF objects..."
	$(MAKE) -C $(EBPF_DIR)

daemon:
	@echo "==> Building aegisd (Control Plane Daemon)..."
	go env -w GOOS=linux
	go env -w CGO_ENABLED=1
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/aegisd $(CMD_DIR)/aegisd/main.go

cli:
	@echo "==> Building aegisctl (Human-in-the-loop CLI)..."
	go env -w GOOS=linux
	go env -w CGO_ENABLED=1
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/aegisctl $(CMD_DIR)/aegisctl/main.go

build: ebpf daemon cli
	@echo "==> Build complete. Binaries are in $(BIN_DIR)/"

clean:
	@echo "==> Cleaning up..."
	$(MAKE) -C $(EBPF_DIR) clean
	rm -rf $(BIN_DIR)
	rm -f aegis.db
	@echo "==> Clean complete."

run: build
	@echo "==> Starting aegisd..."
	sudo ./$(BIN_DIR)/aegisd

test:
	@echo "==> Running Go tests..."
	go test ./...

eval:
	@echo "==> Running Evals Harness..."
	go run $(CMD_DIR)/evalrunner/main.go
