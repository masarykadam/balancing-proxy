# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM golang:1.25.4-bookworm AS builder

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o balancing-proxy .

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM gcr.io/distroless/static-debian12

WORKDIR /app

# Copy binary
COPY --from=builder /app/balancing-proxy /app/balancing-proxy

# Copy config (can be overridden via volume mount)
COPY config.json /app/config.json

# Environment variables
ENV CONFIG_PATH=/app/config.json

# Expose port
EXPOSE 8080

ENTRYPOINT ["/app/balancing-proxy"]
