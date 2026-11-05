# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/snapshots ./cmd/snapshots \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="DegenView Snapshots" \
      org.opencontainers.image.description="Image host for DegenView chart snapshots" \
      org.opencontainers.image.source="https://github.com/degenview/snapshots" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=build /out/snapshots /snapshots
# Owned by the unprivileged user so a fresh named volume is writable.
COPY --from=build --chown=65532:65532 /out/data /data
ENV DATA_DIR=/data LISTEN_ADDR=:8080
VOLUME /data
EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/snapshots", "healthcheck"]
ENTRYPOINT ["/snapshots"]
CMD ["serve"]
