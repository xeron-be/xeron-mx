BINARY  := xeronmx
CLI     := xeronmxctl
PKG     := github.com/xeron-be/xeron-mx
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

# Build the admin SPA into internal/ui/dist, where go:embed picks it up.
# Requires Node; `make build` works without it, serving a page that says so.
.PHONY: ui
ui:
	rm -rf internal/ui/dist/assets internal/ui/dist/index.html
	cd web && npm ci --no-audit --no-fund && npm run build

.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(CLI) ./cmd/$(CLI)

.PHONY: test
test:
	go test ./...

# The race detector needs a C toolchain. On Windows without gcc, use `make test`.
.PHONY: race
race:
	CGO_ENABLED=1 go test -race ./...

.PHONY: fmt
fmt:
	gofmt -w ./cmd ./internal

.PHONY: vet
vet:
	go vet ./...

# What CI runs, and what a pull request should pass before it is opened.
.PHONY: check
check:
	@test -z "$$(gofmt -l ./cmd ./internal)" || { echo "gofmt needed:"; gofmt -l ./cmd ./internal; exit 1; }
	go vet ./...
	CGO_ENABLED=1 go test -race ./...

# Renders the Helm chart in a few combinations and feeds each generated
# xeronmx.yaml through the daemon's own loader. Needs helm on PATH.
.PHONY: chart
chart:
	helm lint deploy/helm/xeronmx
	helm template t deploy/helm/xeronmx >/dev/null
	helm template t deploy/helm/xeronmx --set replicaCount=3 --set cluster.enabled=true 		--set cluster.secret=aaaaaaaaaaaaaaaa --set submission.enabled=true 		--set submission.relayHost=smtp.example.com >/dev/null

.PHONY: docker
docker:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t $(BINARY):$(VERSION) .

.PHONY: run
run: build
	./bin/$(BINARY) -config xeronmx.yaml

# Everything a release needs, from a clean checkout.
.PHONY: all
all: ui build

.PHONY: clean
clean:
	rm -rf bin dist web/node_modules internal/ui/dist/assets internal/ui/dist/index.html
