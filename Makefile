BINARY=dirfuzz
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X github.com/maxvaer/dirfuzz/pkg/version.Version=$(VERSION)"

.PHONY: build test lint clean

build:
	go build $(LDFLAGS) -o $(BINARY) .

test:
	go test ./... -v -race -count=1

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY) $(BINARY).exe
