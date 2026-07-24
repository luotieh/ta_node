# ---- Stage 1: Build ----
FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY cmd/ ./cmd/
COPY internal/ ./internal/

ARG TARGETARCH=arm64
ARG TARGETOS=linux

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -mod=vendor -trimpath -ldflags="-s -w" \
    -o /ta_node ./cmd/ta_node

# ---- Stage 2: Runtime ----
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata libpcap

COPY --from=builder /ta_node /usr/local/bin/ta_node
COPY configs/ /etc/ta_node/configs/
COPY patterns/ /etc/ta_node/patterns/

RUN mkdir -p /var/lib/ta_node/data /var/lib/ta_node/evidence /data/yt

VOLUME ["/var/lib/ta_node/data", "/var/lib/ta_node/evidence", "/data/yt"]
EXPOSE 19090

ENTRYPOINT ["/usr/local/bin/ta_node"]
CMD ["--config", "/etc/ta_node/configs/ta_node.yaml"]
