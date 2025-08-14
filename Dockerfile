# syntax=docker/dockerfile:1

# Build Stage ==================================================================
FROM golang:1.24-alpine AS build

# Install build dependencies
RUN apk --no-cache add git

# Set working directory
WORKDIR /app

# Download Go modules
COPY ./go.mod ./go.sum ./
RUN go mod download

# Copy source and build the application
COPY . .
RUN go build -o gotestwaf \
    -ldflags "-X github.com/wallarm/gotestwaf/internal/version.Version=$(git describe --tags)" \
    ./cmd/gotestwaf


# Main Stage ===================================================================
FROM alpine

# 1. Install runtime dependencies first for better caching
RUN apk add --no-cache tini chromium font-inter fontconfig

# 2. Create a non-root user and group
#    Using -S creates a system user, which is a good practice
RUN addgroup -S gtw && adduser -S -G gtw gtw

# 3. Set the working directory
WORKDIR /app

# 4. Copy the application binary from the build stage
COPY --from=build /app/gotestwaf ./

# 5. Copy other necessary application assets
COPY ./testcases ./testcases
COPY ./config.yaml ./

# 6. Set ownership AFTER copying the files
#    This is the key fix. Now 'gtw' owns the files it needs to run.
RUN chown -R gtw:gtw /app

# 7. Create and set permissions for the reports volume directory
RUN mkdir /app/reports && chown -R gtw:gtw /app/reports

# 8. Switch to the non-root user
USER gtw

# 9. Declare the volume mount point
VOLUME [ "/app/reports" ]

# 10. Run the application using tini as an init system
ENTRYPOINT [ "/sbin/tini", "--", "/app/gotestwaf" ]