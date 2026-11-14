# syntax=docker/dockerfile:1
#
# LANChat managed discovery server (lanchat-discovery).
#
# The build context is the repository root:
#
#   docker build -f deploy/discovery/Dockerfile -t lanchat-discovery .
#
# Optional version metadata:
#
#   docker build -f deploy/discovery/Dockerfile \
#     --build-arg VERSION=v1.0.0 --build-arg COMMIT=$(git rev-parse --short HEAD) \
#     -t lanchat-discovery .

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=
ARG DATE=
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/milad-raeisi/LANChat/internal/buildinfo.Version=${VERSION} \
        -X github.com/milad-raeisi/LANChat/internal/buildinfo.Commit=${COMMIT} \
        -X github.com/milad-raeisi/LANChat/internal/buildinfo.Date=${DATE}" \
      -o /out/lanchat-discovery ./cmd/lanchat-discovery
# The data directory holds the persistent server identity. It must be owned
# by the unprivileged runtime user (65532 = "nonroot" in distroless).
RUN mkdir -p /out/data && chmod 0700 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lanchat-discovery /usr/local/bin/lanchat-discovery
COPY --from=build --chown=65532:65532 /out/data /data
# The default identity path is $XDG_CONFIG_HOME/lanchat-discovery/identity.key,
# so the identity lands in the /data volume while a config file or the
# LANCHAT_DISCOVERY_IDENTITY_FILE variable can still override it.
ENV XDG_CONFIG_HOME=/data
USER 65532:65532
WORKDIR /data
VOLUME ["/data"]
EXPOSE 47780/tcp
# Liveness only (no certificate verification). It targets 127.0.0.1 and the
# port from LANCHAT_DISCOVERY_LISTEN (default 47780); if you change the port
# with a flag or config file instead, override the health check with --addr.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/lanchat-discovery", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/lanchat-discovery"]
CMD ["serve"]
