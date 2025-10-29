# Multi-stage build for Nimbis with all scanning tools
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o nimbis .

# Final stage with all scanning tools
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    git \
    python3 \
    py3-pip \
    curl \
    bash

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install TruffleHog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Checkov via pip
RUN pip3 install --no-cache-dir checkov --break-system-packages

# Copy Nimbis binary from builder
COPY --from=builder /build/nimbis /usr/local/bin/nimbis

# Create workspace
WORKDIR /workspace

# Set Nimbis as entrypoint
ENTRYPOINT ["nimbis"]

# Default to scanning current directory
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="Nimbis"
LABEL org.opencontainers.image.description="Comprehensive security scanning tool"
LABEL org.opencontainers.image.version="0.1.0"
