# Use Golang Alpine image as builder
FROM golang:1.23-alpine AS builder

# Install GCC and dependencies for cgo
RUN apk add --no-cache gcc musl-dev libc6-compat sqlite-dev

# Enable CGO
ENV CGO_ENABLED=1

WORKDIR /app
COPY . .

# Download dependencies
RUN go mod tidy

# Build the Go binary
RUN go build -o app .

# Use a minimal image for final execution
FROM alpine:latest
WORKDIR /root/

# Install required runtime libraries
RUN apk add --no-cache libc6-compat

# Copy the compiled binary from the builder stage
COPY --from=builder /app/app .

# Ensure the binary is executable
RUN chmod +x /root/app

EXPOSE 8080
CMD ["./app"]