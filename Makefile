PROJECT := github.com/icefed/emix
VERSION := $(shell git describe --tags --always --dirty)

all: build

.PHONY: tidy
tidy:
	@go mod tidy

.PHONY: build
build: tidy
	@mkdir -p bin
	@go build -o bin/emix -ldflags="-X $(PROJECT)/version.Version=v$(VERSION)" ./cmd

.PHONY: test
test: tidy
	@go test -v ./...

.PHONY: install
install: build
	@cp bin/emix ~/bin/

.PHONY: clean
clean:
	@rm -rf bin
