#!/bin/bash
# Build script for AeroNyx Rust Crypto library

# Set up environment
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Build for macOS x86_64
echo "Building for x86_64-apple-darwin..."
cargo build --release --target x86_64-apple-darwin

# Build for macOS arm64 (Apple Silicon)
echo "Building for aarch64-apple-darwin..."
cargo build --release --target aarch64-apple-darwin

# Create universal binary
echo "Creating universal binary..."
mkdir -p "$SCRIPT_DIR/target/universal/release"
lipo -create \
  "$SCRIPT_DIR/target/x86_64-apple-darwin/release/libaeronyx_crypto.dylib" \
  "$SCRIPT_DIR/target/aarch64-apple-darwin/release/libaeronyx_crypto.dylib" \
  -output "$SCRIPT_DIR/target/universal/release/libaeronyx_crypto.dylib"

echo "Copying library to project..."
mkdir -p "$SCRIPT_DIR/../PacketTunnel/Resources"
cp "$SCRIPT_DIR/target/universal/release/libaeronyx_crypto.dylib" "$SCRIPT_DIR/../PacketTunnel/Resources/"

echo "Build complete!"
