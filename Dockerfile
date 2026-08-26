# syntax=docker/dockerfile:1

# Pinned to the build host's own architecture. The compile then runs natively
# and cross-compiles to the target below, rather than running the whole Go
# toolchain under QEMU emulation once per non-native platform.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src

# Dependencies first, so edits to source do not invalidate the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
ARG VERSION=dev
# BuildKit supplies these per requested platform.
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/mcp-oauth-proxy .

# static-debian12 carries no shell and no package manager; the binary is the
# entire userland. nonroot resolves to uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/mcp-oauth-proxy /usr/local/bin/mcp-oauth-proxy

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mcp-oauth-proxy"]
