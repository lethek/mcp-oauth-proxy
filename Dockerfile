# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
WORKDIR /src

# Dependencies first, so edits to source do not invalidate the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
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
