.PHONY: test lint vet cover bench fmt check clean proto proto-lint proto-breaking

# Go parameters
GOCMD  := go
GOFLAGS := -count=1

# Packages
PKGS := ./...

## proto: Generate Go code from .proto schemas (buf)
proto:
	buf generate

## proto-lint: Lint .proto schemas (字段命名/enum 前缀等，§1.4 纪律)
proto-lint:
	buf lint

## proto-breaking: Detect breaking wire changes vs main (字段号/enum 只追加保障)
proto-breaking:
	buf breaking --against '.git#branch=main'

## test: Run unit + conformance tests (excludes integration/e2e via build tag)
test:
	$(GOCMD) test $(GOFLAGS) -race -cover $(PKGS)

## test-conf: Run conformance tests only (FakeTransport protocol verification)
test-conf:
	$(GOCMD) test $(GOFLAGS) -race ./conformance/

## test-int: Run integration/e2e tests (requires certificates + ports)
test-int:
	$(GOCMD) test $(GOFLAGS) -race -tags=integration ./v1/ ./ntls/

## test-all: Run all tests including integration
test-all:
	$(GOCMD) test $(GOFLAGS) -race -tags=integration $(PKGS)

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## vet: Run go vet
vet:
	$(GOCMD) vet ./...

## cover: Generate HTML coverage report
cover:
	$(GOCMD) test $(GOFLAGS) -coverprofile=coverage.out $(PKGS)
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## bench: Run benchmark tests
bench:
	$(GOCMD) test $(GOFLAGS) -bench=. -benchmem -run=^$ $(PKGS)

## fmt: Format Go code
fmt:
	gofmt -s -w .
	$(GOCMD) mod tidy

## check: Run all checks (fmt + vet + lint + test)
check: fmt vet lint test

## clean: Remove generated files
clean:
	rm -f coverage.out coverage.html

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //'
