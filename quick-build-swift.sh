#!/bin/bash

# Quick build script for development - builds only debug version and copies to Swift package

set -e

echo "⚡ Quick Swift bindings build (development mode)..."

cd "$(dirname "$0")"
PROJECT_ROOT=$(pwd)

# Step 1: Build debug version and generate bindings
echo "🔨 Building debug version..."
cd "$PROJECT_ROOT/bindings/swift-ffi"

# Clean only bindings
rm -rf bindings/
rm -rf "$PROJECT_ROOT/bindings/swift/Sources/LibSilverFFI/"*.swift

# Build debug version
cargo build

# Generate Swift bindings
echo "🔧 Generating Swift bindings..."
cargo run --bin uniffi-bindgen generate --library ./target/debug/liblibsilver_swift.dylib --language swift --out-dir ./bindings

# Step 2: Copy bindings to Swift package (skip XCFramework for speed)
echo "📋 Copying Swift bindings..."
mkdir -p "$PROJECT_ROOT/bindings/swift/Sources/LibSilverFFI"
cp bindings/*.swift "$PROJECT_ROOT/bindings/swift/Sources/LibSilverFFI/"

# Step 3: Quick test
echo "🧪 Quick test..."
cd "$PROJECT_ROOT/bindings/swift"
swift build

echo "✅ Quick build completed!"
echo "📍 Swift bindings updated: $PROJECT_ROOT/bindings/swift/Sources/LibSilverFFI/"
echo ""
echo "💡 Note: This is a development build. Run 'make swift-all' for production XCFramework."
