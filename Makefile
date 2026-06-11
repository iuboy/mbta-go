.PHONY: test lint vet cover bench fmt check clean

# Go parameters
GOCMD  := go
GOFLAGS := -count=1

# Packages
PKGS := ./...

## test: Run all tests with coverage
test:
	$(GOCMD) test $(GOFLAGS) -race -cover $(PKGS)

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
