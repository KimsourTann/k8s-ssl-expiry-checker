# ──────── Stage 1: Build ──────────
FROM golang:1.23 AS builder

# Set environment variables
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Create and change to the working directory
WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the Go binary
RUN go build -o app .

# ──────── Stage 2: Final ──────────
# FROM gcr.io/distroless/static:nonroot
FROM alpine

# Create non-root user (optional if using distroless:nonroot)
# RUN adduser -D myuser

# Copy binary from builder
COPY --from=builder /app/app /app/app

# Use non-root user (already set in distroless:nonroot)
# USER nonroot:nonroot

# Run the Go app
ENTRYPOINT ["/app/app"]