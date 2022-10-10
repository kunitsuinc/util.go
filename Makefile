SHELL    := /usr/bin/env bash -Eeu -o pipefail
GITROOT  := $(shell git rev-parse --show-toplevel || pwd || echo '.')
PRE_PUSH := ${GITROOT}/.git/hooks/pre-push

.DEFAULT_GOAL := help
.PHONY: help
help: githooks ## display this help documents
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-40s\033[0m %s\n", $$1, $$2}'

.PHONY: githooks
githooks:
	@[[ -f "${PRE_PUSH}" ]] || cp -ai "${GITROOT}/.githooks/pre-push" "${PRE_PUSH}"

.PHONY: lint
lint:  ## Run golangci-lint after go mod tidy
	# tidy
	go mod tidy
	git diff --exit-code go.mod go.sum
	# lint
	# cf. https://golangci-lint.run/usage/linters/
	./.bin/golangci-lint run --fix --sort-results
	git diff --exit-code

.PHONY: test
test: githooks ## Run go test and display coverage
	# test
	go test -v -race -p=4 -parallel=8 -timeout=300s -cover -coverprofile=./coverage.txt ./...
	go tool cover -func=./coverage.txt

.PHONY: ci
ci: lint credits test ## CI command set
