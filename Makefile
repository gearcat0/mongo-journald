# mongo-journald — build, test, and package .deb for amd64 + arm64.
#
#   make test      vet, gofmt check, unit tests
#   make build     cross-compile dist/mongo-journald_<arch>
#   make deb       build + produce dist/*.deb (needs nfpm)
#   make clean
#
# Version: defaults to 0.1.0. Override per build, e.g.
#   make deb VERSION=0.2.0
# Tag-driven versioning arrives with the GoReleaser tier.

VERSION ?= 0.1.0
ARCHES  := amd64 arm64
BIN     := mongo-journald
DISTDIR := dist
LDFLAGS := -s -w -X main.version=$(VERSION)

GO   ?= go
NFPM ?= nfpm

.PHONY: all test build deb clean

all: deb

test:
	$(GO) vet ./...
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) test ./...

# one static, stripped binary per arch (pure Go, no cgo)
$(DISTDIR)/$(BIN)_%:
	@mkdir -p $(DISTDIR)
	GOOS=linux GOARCH=$* CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $@ .

build: $(addprefix $(DISTDIR)/$(BIN)_,$(ARCHES))

deb: build
	@command -v $(NFPM) >/dev/null 2>&1 || { \
		echo "nfpm not found. Install: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; \
		exit 1; }
	@mkdir -p $(DISTDIR)
	@for a in $(ARCHES); do \
		echo "==> packaging $$a (version $(VERSION))"; \
		cp $(DISTDIR)/$(BIN)_$$a $(DISTDIR)/$(BIN); \
		ARCH=$$a VERSION=$(VERSION) $(NFPM) package -f nfpm.yaml -p deb -t $(DISTDIR) || { rm -f $(DISTDIR)/$(BIN); exit 1; }; \
	done
	@rm -f $(DISTDIR)/$(BIN)
	@echo "built:"; ls -1 $(DISTDIR)/*.deb

clean:
	rm -rf $(DISTDIR)
