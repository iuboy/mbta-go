.PHONY: test test-all test-int lint vet cover bench bench-int fmt tidy check clean proto proto-lint proto-breaking gen-certs help

# Go parameters
GOCMD  := go
GOFLAGS := -count=1

# Packages
PKGS := ./...

## proto: Generate Go code from .proto schemas (buf)
proto:
	buf generate

## proto-lint: Lint .proto schemas (字段命名/enum 前缀)
proto-lint:
	buf lint

## proto-breaking: Detect breaking wire changes vs main
proto-breaking:
	buf breaking --against '.git#branch=main'

## test: Run unit tests (excludes integration/e2e via build tag)
test:
	$(GOCMD) test $(GOFLAGS) -race -cover $(PKGS)

## gen-certs: 生成集成/e2e 测试所需证书（TLS + SM2 双证书，gitignored）
gen-certs:
	bash test/data/certificates/gen_certs.sh
	go run test/data/ntls/gen_certs.go

## test-int: Run integration/e2e tests (requires certificates: run `make gen-certs` first)
test-int:
	$(GOCMD) test $(GOFLAGS) -race -tags=integration ./test/ ./v1/ ./ntls/

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

## bench-int: Run integration-tagged E2E benchmarks (requires certificates)
bench-int:
	$(GOCMD) test $(GOFLAGS) -bench=. -benchmem -run=^$ -tags=integration ./test/

## fmt: Format Go code
fmt:
	gofmt -s -w .

## tidy: Tidy module dependencies (separate from fmt to keep formatting side-effect-free)
tidy:
	$(GOCMD) mod tidy

## check: Run all checks (fmt + vet + lint + test)
check: fmt vet lint test

## clean: Remove generated files
clean:
	rm -f coverage.out coverage.html

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //'
