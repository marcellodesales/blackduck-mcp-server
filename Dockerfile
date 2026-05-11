# syntax=docker/dockerfile:1.7

ARG BINARY_NAME=blackduck-mcp
ARG BUILD_IMAGE_TAG=golang:1.24-alpine
ARG RUNTIME_IMAGE_TAG=alpine:3.22.1
ARG GOPROXY=https://proxy.golang.org,direct

# Build the server binary.
FROM --platform=$BUILDPLATFORM ${BUILD_IMAGE_TAG} AS builder

ARG TARGETOS
ARG TARGETARCH
ARG GOPROXY

ENV GOPROXY=${GOPROXY}

WORKDIR /workspace

COPY go.mod go.sum ./

# Cache deps separately from sources.
RUN --mount=type=cache,target=/go/pkg/mod \
    GO111MODULE=on go mod download -x

COPY . .

ARG BINARY_NAME

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GO111MODULE=on GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/${BINARY_NAME} ./cmd/blackduck-mcp

# Runtime image.
FROM ${RUNTIME_IMAGE_TAG} AS blackduck-mcp

WORKDIR /app

# Ensure TLS works for HTTPS upstream calls.
RUN apk add --no-cache ca-certificates

# Run as non-root.
RUN mkdir -p /viasat/certs && addgroup -g 10001 app && adduser -D -u 10001 -G app app

ARG BINARY_NAME
COPY --from=builder /out/${BINARY_NAME} /app/server
RUN chown -R app:app /app /viasat

USER app

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:9090/health || exit 1

ENTRYPOINT ["/app/server"]
