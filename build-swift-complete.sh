#!/bin/bash

# Complete build script for LibSilver Swift bindings
# This script builds the FFI, generates bindings, creates XCFramework, and copies to Swift package

set -e

echo "🚀 Building LibSilver Swift bindings (Complete Workflow)..."

# Navigate to the project root
cd "$(dirname "$0")"
PROJECT_ROOT=$(pwd)

echo "📍 Project root: $PROJECT_ROOT"

# Step 1: Build Swift FFI
echo ""
echo "🔨 Step 1: Building Swift FFI..."
cd "$PROJECT_ROOT/bindings/swift-ffi"

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf target/
rm -rf bindings/
rm -rf LibSilver.xcframework
rm -rf libs/
rm -rf "$PROJECT_ROOT/bindings/swift/LibSilver.xcframework"
rm -rf "$PROJECT_ROOT/bindings/swift/Sources/LibSilverFFI/"*.swift

# Build the dylib for binding generation
echo "📦 Building dylib for binding generation..."
cargo build

# Generate Swift bindings using UniFFI
echo "🔧 Generating Swift bindings..."
cargo run --bin uniffi-bindgen generate --library ./target/debug/liblibsilver_swift.dylib --language swift --out-dir ./bindings

# Add iOS targets if not already added
echo "📱 Adding iOS targets..."
rustup target add aarch64-apple-ios 2>/dev/null || true
rustup target add aarch64-apple-ios-sim 2>/dev/null || true
rustup target add x86_64-apple-ios 2>/dev/null || true
rustup target add aarch64-apple-darwin 2>/dev/null || true
rustup target add x86_64-apple-darwin 2>/dev/null || true

# Build for all iOS targets
echo "🏗️ Building for iOS targets..."
echo "  - Building for iOS device (aarch64-apple-ios)..."
cargo build --release --target=aarch64-apple-ios

echo "  - Building for iOS simulator (aarch64-apple-ios-sim)..."
cargo build --release --target=aarch64-apple-ios-sim

echo "  - Building for iOS simulator (x86_64-apple-ios)..."
cargo build --release --target=x86_64-apple-ios

echo "  - Building for macOS (aarch64-apple-darwin)..."
cargo build --release --target=aarch64-apple-darwin

echo "  - Building for macOS (x86_64-apple-darwin)..."
cargo build --release --target=x86_64-apple-darwin

# Create universal binaries
echo "🔗 Creating universal binaries..."
mkdir -p libs

# iOS Simulator universal binary (x86_64 + arm64)
echo "  - Creating iOS Simulator universal binary..."
lipo -create -output libs/liblibsilver_swift-ios-sim.a \
    target/aarch64-apple-ios-sim/release/liblibsilver_swift.a \
    target/x86_64-apple-ios/release/liblibsilver_swift.a

# macOS universal binary (x86_64 + arm64)
echo "  - Creating macOS universal binary..."
lipo -create -output libs/liblibsilver_swift-macos.a \
    target/aarch64-apple-darwin/release/liblibsilver_swift.a \
    target/x86_64-apple-darwin/release/liblibsilver_swift.a

# iOS device binary (arm64 only)
echo "  - Copying iOS device binary..."
cp target/aarch64-apple-ios/release/liblibsilver_swift.a libs/liblibsilver_swift-ios.a

# Rename module map file
echo "📝 Preparing module map..."
if [ -f "./bindings/libsilver_swiftFFI.modulemap" ]; then
    mv ./bindings/libsilver_swiftFFI.modulemap ./bindings/module.modulemap
fi

# Create XCFramework
echo "📦 Creating XCFramework..."
xcodebuild -create-xcframework \
    -library libs/liblibsilver_swift-ios.a -headers ./bindings \
    -library libs/liblibsilver_swift-ios-sim.a -headers ./bindings \
    -library libs/liblibsilver_swift-macos.a -headers ./bindings \
    -output "LibSilver.xcframework"

# Step 2: Copy to Swift Package
echo ""
echo "📋 Step 2: Copying to Swift package..."

# Copy XCFramework
echo "  - Copying XCFramework..."
cp -r LibSilver.xcframework "$PROJECT_ROOT/bindings/swift/"

# Copy Swift bindings
echo "  - Copying Swift bindings..."
mkdir -p "$PROJECT_ROOT/bindings/swift/Sources/LibSilverFFI"
cp bindings/*.swift "$PROJECT_ROOT/bindings/swift/Sources/LibSilverFFI/"

# Step 3: Test Swift Package
echo ""
echo "🧪 Step 3: Testing Swift package..."
cd "$PROJECT_ROOT/bindings/swift"

echo "  - Building Swift package..."
swift build

echo "  - Running Swift tests..."
swift test

# Cleanup intermediate files
echo ""
echo "🧹 Step 4: Cleaning up intermediate files..."
cd "$PROJECT_ROOT/bindings/swift-ffi"
rm -rf bindings/
rm -rf libs/

echo ""
echo "✅ Build completed successfully!"
echo ""
echo "📍 Outputs:"
echo "  - XCFramework: $PROJECT_ROOT/bindings/swift/LibSilver.xcframework"
echo "  - Swift bindings: $PROJECT_ROOT/bindings/swift/Sources/LibSilverFFI/"
echo "  - Swift package: $PROJECT_ROOT/bindings/swift/"
echo ""
echo "🎉 Ready for distribution via Swift Package Manager!"
