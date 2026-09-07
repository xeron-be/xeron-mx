# UI stage. The admin panel is a Vite/React SPA that the Go binary embeds, so it
# has to exist before the Go build runs.
FROM node:22-alpine AS ui

WORKDIR /ui

# Lockfile first, so a change to the UI source does not re-resolve the tree.
COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY web/ ./
# vite.config.ts writes to ../internal/ui/dist, so the target has to exist here.
RUN mkdir -p /internal/ui/dist && npm run build

# Build stage. CGO stays off: modernc.org/sqlite is pure Go, which is what lets
# the final image be scratch rather than a distro with a libc in it.
FROM golang:1.25-alpine AS build

WORKDIR /src

# Dependencies first, so a code-only change does not re-download the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The compiled SPA, which go:embed picks up from internal/ui/dist.
COPY --from=ui /internal/ui/dist ./internal/ui/dist

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# The data directory is created here so the runtime stage can copy it in already
# owned by the unprivileged uid. A named volume inherits the ownership of the
# image path it shadows, and scratch has no shell to mkdir with — without this
# the volume lands as root:root and the daemon cannot create its database.
RUN mkdir -p /skel/var/lib/xeronmx

RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w \
        -X github.com/xeron-be/xeron-mx/internal/version.Version=${VERSION} \
        -X github.com/xeron-be/xeron-mx/internal/version.Commit=${COMMIT} \
        -X github.com/xeron-be/xeron-mx/internal/version.Date=${DATE}" \
      -o /out/xeronmx ./cmd/xeronmx

# The companion CLI ships in the same image. The runtime stage is scratch, so
# there is no shell to debug with; "kubectl exec -- /xeronmxctl status" is the
# only way to ask a running node how it is doing without a browser.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w \
        -X github.com/xeron-be/xeron-mx/internal/version.Version=${VERSION} \
        -X github.com/xeron-be/xeron-mx/internal/version.Commit=${COMMIT} \
        -X github.com/xeron-be/xeron-mx/internal/version.Date=${DATE}" \
      -o /out/xeronmxctl ./cmd/xeronmxctl

# Runtime stage.
FROM scratch

# Verifying a primary's TLS certificate needs a CA bundle, and the SMTP client
# does that on every STARTTLS. Without this, every delivery over TLS fails.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/xeronmx /xeronmx
COPY --from=build /out/xeronmxctl /xeronmxctl
COPY --from=build --chown=65532:65532 /skel/var/lib/xeronmx /var/lib/xeronmx

# Port 25 below 1024 needs CAP_NET_BIND_SERVICE, which docker-compose grants.
# Running as a non-root uid means a container escape does not land as root.
USER 65532:65532

EXPOSE 25 587 8080
VOLUME ["/var/lib/xeronmx"]

ENV XERONMX_DATA_DIR=/var/lib/xeronmx

ENTRYPOINT ["/xeronmx"]
