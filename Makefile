BINARY    := pathfinder
VERSION   := 1.0.0-beta
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -ldflags "\
  -s -w \
  -X main.GitCommit=$(GIT_COMMIT) \
  -X main.BuildDate=$(BUILD_DATE)"

.PHONY: build
build:
	go build $(LDFLAGS) -o $(BINARY) .

.PHONY: linux-amd64
linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	go build $(LDFLAGS) -o $(BINARY)-linux-amd64 .

.PHONY: linux-arm64
linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	go build $(LDFLAGS) -o $(BINARY)-linux-arm64 .

.PHONY: all
all: linux-amd64 linux-arm64

.PHONY: clean
clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-linux-arm64

.PHONY: test
test:
	go test ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: tidy
tidy:
	go mod tidy
