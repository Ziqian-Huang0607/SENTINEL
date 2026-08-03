# SENTINEL — orchestration Makefile
#
# Components (owned by their own directories, never modified from here):
#   sentinel-scanner   Rust binary           (cargo)
#   sentinel-analyzer  FastAPI on :8710      (python venv)
#   sentinel-reports   FastAPI on :8711      (python venv)
#   sentinel-cli       Go cobra binary       (go build -> bin/sentinel-cli)
#   sentinel-ui        PySide6 desktop GUI   (python -m sentinel_ui)

SHELL := /bin/sh
ROOT  := $(CURDIR)

# Toolchains that may live outside the default PATH in dev environments.
export PATH := $(HOME)/.cargo/bin:$(HOME)/sdk/go/bin:$(PATH)

CARGO  ?= cargo
GO     ?= go
GOFMT  ?= gofmt
DC     ?= docker compose
DOCKER ?= docker

SCANNER_BIN := sentinel-scanner/target/release/sentinel-scanner
# The operator-facing binary lives at bin/sentinel-cli so `./bin/sentinel-cli`
# works from the repo root (the name `sentinel-cli` at root is the Go source
# directory and can never double as the binary path).
CLI_BIN     := $(ROOT)/bin/sentinel-cli

# Python resolution: per-component venv (created by `make build`) when present,
# otherwise the system python3. Recursively expanded (=) on purpose: the venvs
# do not exist when make parses this file, so resolution must happen lazily at
# recipe execution time, after earlier recipe lines have created the venvs.
ANALYZER_PY = $(shell [ -x "$(ROOT)/sentinel-analyzer/.venv/bin/python" ] && echo "$(ROOT)/sentinel-analyzer/.venv/bin/python" || echo python3)
REPORTS_PY  = $(shell [ -x "$(ROOT)/sentinel-reports/.venv/bin/python" ] && echo "$(ROOT)/sentinel-reports/.venv/bin/python" || echo python3)
UI_PY       = $(shell [ -x "$(ROOT)/sentinel-ui/.venv/bin/python" ] && echo "$(ROOT)/sentinel-ui/.venv/bin/python" || echo python3)

# Python used for the repo-level test harness (needs pytest/httpx/pydantic —
# all present in the analyzer venv; `make test-integration` ensures them).
TEST_PY = $(ANALYZER_PY)

# ruff runs via the analyzer venv python (installed by requirements-test.txt).

.PHONY: build build-scanner build-cli build-python up down test test-unit test-ui \
        test-integration test-e2e test-llm-memory test-build lint fmt ui clean \
        venv-analyzer build-venv-analyzer venv-reports build-venv-reports venv-ui build-venv-ui

## build: compile scanner + cli and create python venvs for the services/UI
build: build-scanner build-cli build-python

build-scanner:
	cd sentinel-scanner && $(CARGO) build --release

build-cli:
	mkdir -p bin
	cd sentinel-cli && $(GO) build -o "$(CLI_BIN)" .

build-python: build-venv-analyzer build-venv-reports build-venv-ui

# Venv creation and pip installs live in separate targets because GNU make
# expands a target's whole recipe before running its first line — the python
# path variables can only resolve a venv that already exists when the
# depending target starts.
venv-analyzer:
	python3 -m venv sentinel-analyzer/.venv

build-venv-analyzer: venv-analyzer
	"$(ANALYZER_PY)" -m pip install --upgrade pip
	"$(ANALYZER_PY)" -m pip install -r sentinel-analyzer/requirements.txt
	"$(ANALYZER_PY)" -m pip install -r requirements-test.txt

venv-reports:
	python3 -m venv sentinel-reports/.venv

build-venv-reports: venv-reports
	"$(REPORTS_PY)" -m pip install --upgrade pip
	"$(REPORTS_PY)" -m pip install -r sentinel-reports/requirements.txt
	"$(REPORTS_PY)" -m pip install -r sentinel-reports/requirements-fallback.txt
	"$(REPORTS_PY)" -m pip install -r requirements-test.txt

venv-ui:
	python3 -m venv sentinel-ui/.venv

build-venv-ui: venv-ui
	"$(UI_PY)" -m pip install --upgrade pip
	"$(UI_PY)" -m pip install -r sentinel-ui/requirements.txt
	"$(UI_PY)" -m pip install -r requirements-test.txt

## up: start analyzer + reports (+ ollama when using: make up PROFILES=--profile llm)
up:
	./scripts/services.sh start

down:
	./scripts/services.sh stop

## test: unit + ui + integration + e2e suites
test: test-unit test-ui test-integration test-e2e

test-unit:
	cd sentinel-scanner && $(CARGO) test
	cd sentinel-analyzer && "$(ANALYZER_PY)" -m pytest -q
	cd sentinel-cli && $(GO) test ./...
	cd sentinel-reports && "$(REPORTS_PY)" -m pytest -q
	"$(TEST_PY)" -m pytest test/unit -q

## test-ui: offscreen Qt smoke/unit tests for the desktop GUI
test-ui:
	cd sentinel-ui && QT_QPA_PLATFORM=offscreen "$(UI_PY)" -m pytest tests -q

## test-integration: live analyzer+reports via compose, then pipeline + API tests
test-integration:
	./scripts/services.sh start
	"$(TEST_PY)" -m pip install -q -r requirements-test.txt
	"$(TEST_PY)" test/integration/test_pipeline.py
	"$(TEST_PY)" -m pytest test/integration/test_api.py -v

## test-e2e: full CLI scan of 127.0.0.1/32 followed by output/report validators
test-e2e:
	./scripts/services.sh start
	"$(CLI_BIN)" scan --target 127.0.0.1/32 --tier daily --output json --yes
	"$(TEST_PY)" test/e2e/validate_output.py
	"$(TEST_PY)" test/e2e/validate_report.py

## test-llm-memory: hardware gates for the 8GB M1 Air budget (SKIP when no ollama)
test-llm-memory:
	"$(TEST_PY)" test/hardware/test_memory.py --max-mb 5120
	"$(TEST_PY)" test/hardware/test_inference.py --max-seconds 60

## test-build: verify all release/cross builds compile
test-build:
	cd sentinel-scanner && $(CARGO) build --release
	cd sentinel-cli && GOOS=darwin GOARCH=arm64 $(GO) build -o /tmp/sentinel-cli-darwin-arm64 .
	cd sentinel-cli && GOOS=linux GOARCH=amd64 $(GO) build -o /tmp/sentinel-cli-linux-amd64 .
	$(DOCKER) build -t sentinel-analyzer sentinel-analyzer
	$(DOCKER) build -t sentinel-reports sentinel-reports

lint:
	cd sentinel-scanner && $(CARGO) clippy --all-targets -- -D warnings
	"$(ANALYZER_PY)" -m ruff check sentinel-analyzer sentinel-reports sentinel-ui test
	cd sentinel-cli && $(GO) vet ./...
	@cd sentinel-cli && files=$$($(GOFMT) -l .); \
		if [ -n "$$files" ]; then echo "gofmt needed on: $$files"; exit 1; fi

fmt:
	cd sentinel-scanner && $(CARGO) fmt
	"$(ANALYZER_PY)" -m ruff check --fix sentinel-analyzer sentinel-reports sentinel-ui test || true
	"$(ANALYZER_PY)" -m ruff format sentinel-analyzer sentinel-reports sentinel-ui test
	cd sentinel-cli && $(GOFMT) -w .

ui:
	cd sentinel-ui && "$(UI_PY)" -m sentinel_ui

clean:
	-cd sentinel-scanner && $(CARGO) clean
	rm -rf bin
	rm -f sentinel-cli/sentinel-cli scan.json analysis.json
	rm -f sentinel-report.json sentinel-report.pdf sentinel-report.sarif
	-$(DC) down --remove-orphans
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache
