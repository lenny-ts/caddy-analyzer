BIN=caddy-analyze

GOMU_VERSION ?= v0.3.0
MUTATION_TARGET ?= .
MUTATION_WORKERS ?= 4

default: clean lint test build

help:
	@echo "Usage:"
	@echo "  make build    Build binary + install shell completion"
	@echo "  make run      Build and run (ARGS=...)"
	@echo "  make install  Install via go install"
	@echo "  make test     Run all tests"
	@echo "  make mutation  Run mutation testing with gomu (targeted with MUTATION_TARGET=./pkg/...)"
	@echo "  make lint     Run go vet"
	@echo "  make clean    Remove binary"

$(BIN):
	go build -o $@ ./cmd/caddy-analyze/

build: $(BIN) completion

run: build
	./$(BIN) $(ARGS)

install:
	go install ./cmd/caddy-analyze/

completion: $(BIN)
	@shell=$$(basename "$${SHELL:-bash}"); \
	case "$$shell" in \
		bash) \
			dir=$${XDG_DATA_HOME:-$$HOME/.local/share}/bash-completion/completions; \
			mkdir -p "$$dir"; \
			./$(BIN) completion bash > "$$dir/caddy-analyze"; \
			echo "bash completion -> $$dir/caddy-analyze"; \
			;; \
		zsh) \
			dir=$${ZSH_COMPLETIONS:-$$HOME/.zsh/completion}; \
			mkdir -p "$$dir"; \
			./$(BIN) completion zsh > "$$dir/_caddy-analyze"; \
			echo "zsh completion -> $$dir/_caddy-analyze"; \
			echo "Add 'fpath=($$dir \$$fpath)' to your .zshrc"; \
			;; \
		fish) \
			dir=$$HOME/.config/fish/completions; \
			mkdir -p "$$dir"; \
			./$(BIN) completion fish > "$$dir/caddy-analyze.fish"; \
			echo "fish completion -> $$dir/caddy-analyze.fish"; \
			;; \
		*) \
			echo "shell $$shell not supported for completion"; \
			;; \
	esac

test:
	go test ./...

mutation:
	go run github.com/sivchari/gomu/cmd/gomu@$(GOMU_VERSION) run $(MUTATION_TARGET) --incremental=false --threshold 0 --fail-on-gate=false --workers $(MUTATION_WORKERS) --output json

lint:
	go vet ./...

clean:
	rm -f $(BIN)

.PHONY: help build run install completion test mutation lint clean
