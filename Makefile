# LibSilver Swift Bindings Makefile

.PHONY: swift-ffi swift-package swift-clean swift-test swift-all help

# Default target
help:
	@echo "LibSilver Swift Bindings Build Commands:"
	@echo ""
	@echo "  make swift-all     - Complete build: FFI + Package + Test"
	@echo "  make swift-ffi     - Build only the Rust FFI layer"
	@echo "  make swift-package - Copy FFI outputs to Swift package"
	@echo "  make swift-test    - Test the Swift package"
	@echo "  make swift-clean   - Clean all build artifacts"
	@echo ""

# Complete workflow: Build FFI, copy to package, and test
swift-all:
	@echo "🚀 Running complete Swift bindings build..."
	./build-swift-complete.sh

# Build only the Rust FFI layer
swift-ffi:
	@echo "🔨 Building Swift FFI layer..."
	cd bindings/swift-ffi && ./build-swift.sh

# Copy FFI outputs to Swift package (manual step)
swift-package:
	@echo "📋 Copying FFI outputs to Swift package..."
	@if [ ! -f "bindings/swift-ffi/LibSilver.xcframework" ]; then \
		echo "❌ XCFramework not found. Run 'make swift-ffi' first."; \
		exit 1; \
	fi
	cp -r bindings/swift-ffi/LibSilver.xcframework bindings/swift/
	mkdir -p bindings/swift/Sources/LibSilverFFI
	cp bindings/swift-ffi/bindings/*.swift bindings/swift/Sources/LibSilverFFI/
	@echo "✅ Copied to Swift package"

# Test the Swift package
swift-test:
	@echo "🧪 Testing Swift package..."
	cd bindings/swift && swift build && swift test

# Clean all build artifacts
swift-clean:
	@echo "🧹 Cleaning Swift build artifacts..."
	rm -rf bindings/swift-ffi/target/
	rm -rf bindings/swift-ffi/bindings/
	rm -rf bindings/swift-ffi/LibSilver.xcframework
	rm -rf bindings/swift-ffi/libs/
	rm -rf bindings/swift/LibSilver.xcframework
	rm -rf bindings/swift/.build/
	@echo "✅ Cleaned all artifacts"
