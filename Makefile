# Agentic-Recon — build / lint / test.
# Quality gates (AGENTS.md): gofmt, go vet, go test -race, go build.

BIN_DIR := bin

.PHONY: all ci lint test build clean

all: lint test build

ci: lint test build

lint:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
	  echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi
	go vet ./...

test:
	go test -race ./...

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -o $(BIN_DIR)/ ./cmd/...

clean:
	rm -rf $(BIN_DIR)
