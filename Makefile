PROJECT := github.com/icefed/emix
VERSION := $(shell git describe --tags --always --dirty)
LOCALBIN ?= ~/bin

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

.PHONY: cover
cover: tidy
	@go test -v ./... -coverprofile=cover.out

.PHONY: install
install: build
	@cp bin/* $(LOCALBIN)

.PHONY: clean
clean:
	@rm -rf bin
