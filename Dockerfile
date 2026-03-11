FROM rust:latest as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml ./

# Copy source tree
COPY src ./src
COPY context ./context

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/smf /app/smf
COPY --from=builder /app/context /app/context

# Expose port
EXPOSE 8080

# Run the binary
CMD ["/app/smf"]
