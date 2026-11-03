BIN ?= bin/app

.PHONY: build build-proxy-helper test check fmt lint vuln clean

build:
	go build ./...

build-proxy-helper:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o bin/klorq-proxy-helper-linux-arm64 ./cmd/klorq-proxy-helper

test:
	go test -race -count=1 ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...

fmt:
	gofmt -w .

lint:
	golangci-lint config verify
	golangci-lint run ./...

vuln:
	govulncheck ./...

clean:
	rm -rf bin
