# syntax=docker/dockerfile:1.7
#
# circulusd node control-plane reference image — DEVELOPMENT/REFERENCE ONLY.
#
# Builds the pure-Go control-plane daemons (platformd, platformd-dev, agentd,
# executord) and the platformctl client into a single minimal image. It does
# NOT bundle workerd, celld, nsjail, the Docker engine, Firecracker, or any
# Worker bundle: those are separate digest-pinned airgap artifacts (see
# deploy/airgap/release-manifest.json), several of which are still unresolved.
# None of the production capabilities are wired in these binaries; they serve
# only their diagnostic control sockets and report every capability as
# NOT_WIRED. See docs/deployment-k8s.md. Build from the repository root:
#
#   docker build -f deploy/images/Dockerfile -t circulusd:0.3.0-dev .
#
# This image has NOT been built or run in this workspace (no container runtime
# was available); treat it as unverified reference scaffolding.

ARG GO_VERSION=1.25.3
# busybox provides a shell so the entrypoint can clear a stale control socket
# after an ungraceful restart (the daemons fail-closed on a pre-existing socket
# and only unlink on graceful shutdown) and so the socket-dir init step has
# chmod/chown. Repoint RUNTIME_BASE at an air-gapped mirror as needed.
ARG RUNTIME_BASE=busybox:1.37

FROM golang:${GO_VERSION}-bookworm AS build
# The daemons need no cgo (they use golang.org/x/sys, not cgo); build static.
# GOWORK=off so the single-module go.work does not alter module resolution.
ENV CGO_ENABLED=0 GOWORK=off GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH
RUN set -eux; \
    export GOOS=linux; \
    # Honor buildx cross-builds via TARGETARCH; for a plain `docker build`
    # (TARGETARCH unset) use the builder's native arch so the binary matches the
    # runtime base image's arch.
    if [ -n "${TARGETARCH:-}" ]; then export GOARCH="${TARGETARCH}"; fi; \
    mkdir -p /out; \
    for cmd in platformd platformd-dev agentd executord platformctl; do \
      go build -trimpath -ldflags='-s -w' -o "/out/${cmd}" "./cmd/${cmd}"; \
    done

FROM ${RUNTIME_BASE}
LABEL org.opencontainers.image.title="circulusd-node" \
      org.opencontainers.image.description="circulusd single-node control-plane daemons (development/reference only; not production, not a Kubernetes scheduler)" \
      org.opencontainers.image.source="https://github.com/hancomac/circulusd" \
      org.opencontainers.image.version="0.3.0-dev" \
      circulusd.dev/production-eligible="false"
COPY --from=build \
     /out/platformd /out/platformd-dev /out/agentd /out/executord /out/platformctl \
     /usr/local/bin/
# Run as a fixed non-root uid/gid (65532 is the conventional non-root id the
# Helm chart authorizes on the control sockets). The daemons resolve identity
# via geteuid(2), not a passwd entry, so no /etc/passwd user is required.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/platformd-dev"]
