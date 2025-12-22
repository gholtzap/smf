#!/bin/bash

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_info "Starting SMF setup for macOS ARM..."

if [ "$(uname)" != "Darwin" ]; then
    log_error "This script is designed for macOS. Current OS: $(uname)"
    exit 1
fi

if [ "$(uname -m)" != "arm64" ]; then
    log_warn "This script is optimized for ARM (Apple Silicon). Detected: $(uname -m)"
fi

log_info "Checking prerequisites..."

if ! command -v brew &> /dev/null; then
    log_error "Homebrew is not installed. Please install it from https://brew.sh"
    exit 1
fi
log_info "✓ Homebrew is installed ($(brew --version | head -n1))"

if ! command -v rustc &> /dev/null || ! command -v cargo &> /dev/null; then
    log_warn "Rust is not installed. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    log_info "✓ Rust installed successfully"
else
    log_info "✓ Rust is installed ($(rustc --version))"
fi

if ! command -v mongod &> /dev/null; then
    log_warn "MongoDB is not installed. Installing via Homebrew..."
    brew tap mongodb/brew
    brew install mongodb-community
    log_info "✓ MongoDB installed successfully"
else
    log_info "✓ MongoDB is installed"
fi

log_info "Starting MongoDB service..."
if brew services list | grep mongodb-community | grep started &> /dev/null; then
    log_info "✓ MongoDB service is already running"
else
    brew services start mongodb-community
    sleep 2
    if brew services list | grep mongodb-community | grep started &> /dev/null; then
        log_info "✓ MongoDB service started successfully"
    else
        log_error "Failed to start MongoDB service"
        exit 1
    fi
fi

if [ ! -f .env ]; then
    log_info "Creating .env file from .env.example..."
    cp .env.example .env
    log_info "✓ .env file created"
    log_warn "Please review and update .env file with your configuration"
else
    log_info "✓ .env file already exists"
fi

log_info "Building SMF (release mode)..."
cargo build --release

log_info ""
log_info "=========================================="
log_info "Setup completed successfully!"
log_info "=========================================="
log_info ""
log_info "To run the SMF server:"
log_info "  cargo run --release"
log_info ""
log_info "Or directly:"
log_info "  ./target/release/smf"
log_info ""
log_info "The server will start on http://localhost:8080"
log_info ""
log_warn "Note: Some services (NRF, UPF, PCF, UDM, CHF) may not be available."
log_warn "Update the .env file with proper URIs for these services."
log_info ""
