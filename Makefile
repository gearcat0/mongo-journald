# mongo-journald — test, validate, and build .deb packages.
#
#   make test     go vet, gofmt check, unit tests
#   make check    validate .goreleaser.yaml
#   make deb      build amd64 + arm64 .deb locally (GoReleaser snapshot -> dist/)
#   make clean
#
# GoReleaser (.goreleaser.yaml) is the single source of truth for packaging,
# so `make deb` produces the same artifacts CI does. Releases are tag-driven:
# push a tag like v0.2.0 and .github/workflows/release.yml runs
# `goreleaser release`, attaching the .deb packages + checksums to a GitHub
# Release — no manual copying from a build box.

GO         ?= go
GORELEASER ?= goreleaser

.PHONY: all test check deb clean

all: test deb

test:
	$(GO) vet ./...
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) test ./...

check:
	$(GORELEASER) check

deb:
	@command -v $(GORELEASER) >/dev/null 2>&1 || { \
		echo "goreleaser not found. Install: go install github.com/goreleaser/goreleaser/v2@latest"; \
		exit 1; }
	$(GORELEASER) release --snapshot --clean
	@echo; echo "built:"; ls -1 dist/*.deb

clean:
	rm -rf dist
