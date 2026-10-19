# Developer and CI entry points. `make check` runs locally what the required
# CI jobs (srs, go, lint, site, security) check; `make integration` runs the
# linux-integration job's script.
#
# Tool versions match .github/workflows/ci.yml; keep them in step.

GOLANGCI_LINT_VERSION ?= v2.14.0
GOVULNCHECK_VERSION   ?= v1.9.0
GORELEASER_VERSION    ?= v2.18.2

GO      ?= go
PYTHON  ?= python3
NPM     ?= npm
BUILD   := build

# Use an installed golangci-lint when it is the pinned version; otherwise run
# the pinned version through `go run` (slower on first use, then cached).
GOLANGCI_LINT ?= $(shell command -v golangci-lint >/dev/null 2>&1 && golangci-lint version --short 2>/dev/null | grep -qx '$(GOLANGCI_LINT_VERSION:v%=%)' && echo golangci-lint || echo '$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)')
GORELEASER    ?= $(GO) run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)

.DEFAULT_GOAL := help

.PHONY: help
help: ## List targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build smcpd and smcpctl into build/bin
	$(GO) build ./...
	$(GO) build -trimpath -o $(BUILD)/bin/ ./cmd/smcpd ./cmd/smcpctl

.PHONY: test
test: ## Run all Go tests
	$(GO) test ./...

.PHONY: race
race: ## Run Go tests with the race detector (-short)
	$(GO) test -race -short ./...

.PHONY: vet
vet: ## go vet (including the hostile suite's build tag)
	$(GO) vet ./...
	$(GO) vet -tags hostile ./internal/hostile/

.PHONY: fmt
fmt: ## Format Go code
	gofmt -w $$(git ls-files '*.go')

.PHONY: fmt-check
fmt-check: ## Fail when Go code is not gofmt-formatted
	@out=$$(gofmt -l $$(git ls-files '*.go')); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

.PHONY: tidy-check
tidy-check: ## Fail when go.mod or go.sum is not tidy
	$(GO) mod tidy -diff

.PHONY: lint
lint: ## golangci-lint (pinned version, .golangci.yml)
	$(GOLANGCI_LINT) run ./...

.PHONY: srs
srs: ## Regenerate Secure_MCP_Gateway_SRS.md from srs_build/
	$(PYTHON) -I srs_build/gen.py . Secure_MCP_Gateway_SRS.md

.PHONY: srs-check
srs-check: ## Fail when the committed SRS differs from srs_build/
	@mkdir -p $(BUILD)
	$(PYTHON) -I srs_build/gen.py . $(BUILD)/srs.md
	diff -u Secure_MCP_Gateway_SRS.md $(BUILD)/srs.md

.PHONY: openapi
openapi: ## Regenerate site/data/openapi.json (the control API document) from the Go sources
	$(GO) run ./tools/openapi

site/node_modules: site/package-lock.json
	cd site && $(NPM) ci --no-audit --no-fund
	@touch site/node_modules

.PHONY: site-typecheck
site-typecheck: site/node_modules ## Typecheck the site (tsc --noEmit) and run its unit tests
	cd site && npx --no-install tsc --noEmit
	cd site && $(NPM) test

.PHONY: site
site: site/node_modules ## Typecheck, test and build the static site into site/out, then check its pages and links
	cd site && npx --no-install tsc --noEmit
	cd site && $(NPM) test
	cd site && $(NPM) run build
	cd site && $(NPM) run check-out

console/node_modules: console/package-lock.json
	cd console && $(NPM) ci --no-audit --no-fund
	@touch console/node_modules

.PHONY: console
console: console/node_modules ## Typecheck and build the console into console/dist (commit the result)
	cd console && $(NPM) run build

.PHONY: console-check
console-check: console ## Fail when the committed console/dist differs from a fresh build
	@out=$$(git status --porcelain -- console/dist); if [ -n "$$out" ]; then echo "console/dist is stale; commit the rebuilt files:"; echo "$$out"; exit 1; fi

.PHONY: console-e2e
console-e2e: console/node_modules ## Playwright acceptance tests of the console on Chromium, Firefox and WebKit against a real smcpd
	cd console && npx --no-install playwright install chromium firefox webkit && $(NPM) run test:e2e

.PHONY: vuln
vuln: ## govulncheck and npm audit gate
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	scripts/npm-audit-gate.sh site
	scripts/npm-audit-gate.sh console

.PHONY: status
status: ## Full tests with coverage, then build/reqreport.{json,md} and build/status.json
	@mkdir -p $(BUILD)
	@rc=0; $(GO) test -race -json -coverpkg=./... -coverprofile=$(BUILD)/cover.out ./... > $(BUILD)/go-test.json || rc=$$?; \
	$(GO) run ./tools/reqreport -in $(BUILD)/go-test.json -coverprofile $(BUILD)/cover.out || exit $$?; \
	exit $$rc

.PHONY: hostile
hostile: ## Hostile backend fixture suite (SRS Appendix L); writes build/hostile.json and build/hostile.md
	@mkdir -p $(BUILD)
	$(GO) test -tags hostile -count=1 -run TestHostileFixtures ./internal/hostile/
	@cat $(BUILD)/hostile.md

.PHONY: conformance
conformance: ## MCP conformance suite over the schema examples (FR-12.9); writes build/conformance.md
	@mkdir -p $(BUILD)
	SMCP_CONFORMANCE_REPORT=$(CURDIR)/$(BUILD)/conformance.md $(GO) test -count=1 -run TestConformanceSuite ./internal/conformance/
	@cat $(BUILD)/conformance.md

.PHONY: integration
integration: ## Bootstrap, run smcpd, drive an MCP client, verify the journal
	scripts/ci-integration.sh

.PHONY: check
check: srs-check build vet fmt-check tidy-check race lint site-typecheck ## Everything the required CI jobs check (fast form)

.PHONY: check-full
check-full: check site vuln integration console-check console-e2e ## check plus site build, vulnerability scans, the integration run and the console job

.PHONY: release-snapshot
release-snapshot: ## Build release archives locally into build/dist (no publishing)
	SMCP_BUILD_REFSERVER=$$( [ -d cmd/smcp-refserver ] && echo 1 || echo 0 ) \
	GORELEASER_CURRENT_TAG=$$(git tag -l 'v*' --sort=-version:refname | head -n1 | grep . || echo v0.0.0) \
	$(GORELEASER) release --snapshot --clean $$( [ -n "$${MINISIGN_KEY_FILE:-}" ] || echo --skip=sign )

.PHONY: clean
clean: ## Remove build outputs
	rm -rf $(BUILD) site/out
