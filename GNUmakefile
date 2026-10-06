GOLANGCI_LINT = github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
GOTESTSUM     = gotest.tools/gotestsum@v1.13.0


.PHONY: help
help: ## shows this help
	@awk 'BEGIN { FS = ":.*## " } /^[a-z-]+:.*## / { printf "%-6s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: lint
lint: ## runs linter
	go run $(GOLANGCI_LINT) run

.PHONY: test
test: ## performs tests
	go run $(GOTESTSUM) -- -race -coverprofile=coverage.out ./...

.PHONY: run
run: ## runs the exporter on localhost, flags via ARGS="..."
	go run . $(ARGS)
