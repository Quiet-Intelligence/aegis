.PHONY: all ebpf daemon cli tui build clean run test eval install-deps everything

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

tui:
	@echo "==> Building aegis-tui (Terminal UI)..."
	go env -w GOOS=linux
	go env -w CGO_ENABLED=1
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/aegis-tui $(CMD_DIR)/aegis-tui/main.go

build: ebpf daemon cli tui
	@echo "==> Build complete. Binaries are in $(BIN_DIR)/"

install-deps:
	@echo "==> Installing host dependencies..."
	bash scripts/install_deps.sh

everything: install-deps build
	@echo "==> Setup complete! Launching TUI..."
	./$(BIN_DIR)/aegis-tui

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
