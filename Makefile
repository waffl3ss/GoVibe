.PHONY: build clean install deps build-proxy

BINARY=govibe
GOFLAGS=-ldflags="-s -w"

# Standard build (may not work well with proxychains)
build: deps
	go build $(GOFLAGS) -o $(BINARY) .

# Build with CGO for proxychains compatibility
# Forces use of system resolver instead of Go's native resolver
build-proxy: deps
	CGO_ENABLED=1 go build $(GOFLAGS) -tags netcgo -o $(BINARY) .

build-all: deps
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o $(BINARY)-linux-arm64 .
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o $(BINARY)-windows-amd64.exe .
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -o $(BINARY)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -o $(BINARY)-darwin-arm64 .

deps:
	go mod tidy

clean:
	rm -f $(BINARY) $(BINARY)-*

install: build-proxy
	cp $(BINARY) /usr/local/bin/

test:
	go test -v ./...
