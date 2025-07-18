#!/bin/bash

# Build script for LibSilver Swift bindings using UniFFI

set -e

echo "🔨 Building LibSilver Swift bindings..."

# Navigate to the Swift FFI directory
cd "$(dirname "$0")"

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf target/
rm -rf bindings/
rm -rf ios/LibSilver.xcframework

# Build the dylib for binding generation
echo "📦 Building dylib for binding generation..."
cargo build

# Generate Swift bindings using UniFFI
echo "🔧 Generating Swift bindings..."
cargo run --bin uniffi-bindgen generate --library ./target/debug/liblibsilver_swift.dylib --language swift --out-dir ./bindings

# Add iOS targets
echo "📱 Adding iOS targets..."
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim
rustup target add x86_64-apple-ios
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-darwin

# Build for all iOS targets
echo "🏗️ Building for iOS targets..."
cargo build --release --target=aarch64-apple-ios
cargo build --release --target=aarch64-apple-ios-sim
cargo build --release --target=x86_64-apple-ios
cargo build --release --target=aarch64-apple-darwin
cargo build --release --target=x86_64-apple-darwin

# Create universal binaries
echo "🔗 Creating universal binaries..."
mkdir -p libs

# iOS Simulator universal binary (x86_64 + arm64)
lipo -create -output libs/liblibsilver_swift-ios-sim.a \
    target/aarch64-apple-ios-sim/release/liblibsilver_swift.a \
    target/x86_64-apple-ios/release/liblibsilver_swift.a

# macOS universal binary (x86_64 + arm64)
lipo -create -output libs/liblibsilver_swift-macos.a \
    target/aarch64-apple-darwin/release/liblibsilver_swift.a \
    target/x86_64-apple-darwin/release/liblibsilver_swift.a

# iOS device binary (arm64 only)
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

# Copy Swift bindings to the main Swift package
echo "📋 Copying Swift bindings..."
mkdir -p ../swift/Sources/LibSilverFFI
cp bindings/*.swift ../swift/Sources/LibSilverFFI/
cp -r LibSilver.xcframework ../swift/

echo "✅ Swift bindings build complete!"
echo "📍 XCFramework location: $(pwd)/LibSilver.xcframework"
echo "📍 Swift bindings location: $(pwd)/../swift/Sources/LibSilverFFI/"

# Cleanup intermediate files
echo "🧹 Cleaning up..."
rm -rf bindings/
rm -rf libs/

echo "🎉 Build completed successfully!"
