# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags "-s -w \
        -X github.com/victor-akande/weistack/internal/version.Version=$VERSION \
        -X github.com/victor-akande/weistack/internal/version.Commit=$COMMIT \
        -X github.com/victor-akande/weistack/internal/version.Date=$DATE" \
      -o /out/weistack ./cmd/weistack \
    # The runtime user (65532) must own the data directory.
    && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="WeiStack" \
      org.opencontainers.image.description="Local emulator of core Huawei Cloud services" \
      org.opencontainers.image.source="https://github.com/victor-akande/weistack" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/weistack /weistack
COPY --from=build --chown=65532:65532 /out/data /data

# Inside a container the emulator must listen on all interfaces to be
# reachable through a published port; outside it defaults to loopback.
ENV WEISTACK_HOST=0.0.0.0 \
    WEISTACK_DATA_DIR=/data

EXPOSE 8780
VOLUME ["/data"]
USER 65532:65532

HEALTHCHECK --interval=30s --timeout=3s --start-period=2s --retries=3 \
    CMD ["/weistack", "healthcheck"]

ENTRYPOINT ["/weistack"]
