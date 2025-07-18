# Building LibSilver Swift Bindings

This document explains how to build the Swift bindings for LibSilver using the automated build system.

## Quick Start

### Option 1: Complete Build (Recommended)
```bash
# Build everything: FFI + XCFramework + Swift Package + Tests
make swift-all
```

### Option 2: Development Build (Faster)
```bash
# Quick build for development (debug mode, no XCFramework)
./quick-build-swift.sh
```

## Build Commands

### Using Makefile (Recommended)

```bash
# Show all available commands
make help

# Complete production build
make swift-all

# Build only the Rust FFI layer
make swift-ffi

# Copy FFI outputs to Swift package
make swift-package

# Test the Swift package
make swift-test

# Clean all build artifacts
make swift-clean
```

### Using Scripts Directly

```bash
# Complete production build
./build-swift-complete.sh

# Quick development build
./quick-build-swift.sh

# FFI only (from bindings/swift-ffi/)
cd bindings/swift-ffi && ./build-swift.sh
```

## Build Process Explained

### 1. FFI Layer (`/bindings/swift-ffi/`)
- **Purpose**: Builds Rust library with UniFFI bindings
- **Outputs**:
  - Static libraries for all Apple platforms
  - Generated Swift bindings
  - C headers and module maps
  - XCFramework (universal binary)

### 2. Swift Package (`/bindings/swift/`)
- **Purpose**: Swift Package Manager distribution
- **Contains**:
  - XCFramework (copied from FFI layer)
  - Generated Swift bindings (copied from FFI layer)
  - Idiomatic Swift wrapper APIs
  - Tests and documentation

### 3. Automatic Copy Process
The build scripts automatically:
1. Build the Rust FFI layer
2. Generate Swift bindings using UniFFI
3. Create XCFramework for all Apple platforms
4. Copy everything to the Swift package directory
5. Run tests to verify everything works

## Directory Structure

```
libsilver/
├── build-swift-complete.sh     # Complete build script
├── quick-build-swift.sh        # Development build script
├── Makefile                    # Build commands
├── BUILD-SWIFT.md             # This file
└── bindings/
    ├── swift-ffi/             # Rust FFI layer
    │   ├── src/lib.rs         # UniFFI implementation
    │   ├── Cargo.toml         # Rust dependencies
    │   ├── build-swift.sh     # FFI build script
    │   └── build.rs           # Build configuration
    └── swift/                 # Swift package
        ├── Package.swift      # SPM configuration
        ├── LibSilver.xcframework  # Universal binary (generated)
        ├── Sources/
        │   ├── LibSilver/     # Swift wrapper APIs
        │   └── LibSilverFFI/  # Generated bindings (generated)
        └── Tests/             # Swift tests
```

## Development Workflow

### For Rust Changes
1. Modify Rust code in `src/` or `bindings/swift-ffi/src/`
2. Run quick build: `./quick-build-swift.sh`
3. Test: `cd bindings/swift && swift test`

### For Swift Wrapper Changes
1. Modify Swift code in `bindings/swift/Sources/LibSilver/`
2. Test: `cd bindings/swift && swift test`

### For Production Release
1. Run complete build: `make swift-all`
2. Verify all tests pass
3. The Swift package is ready for distribution

## Requirements

### System Requirements
- macOS with Xcode installed
- Rust toolchain
- Swift 5.7+

### Rust Targets (automatically installed)
- `aarch64-apple-ios` (iOS device)
- `aarch64-apple-ios-sim` (iOS simulator ARM64)
- `x86_64-apple-ios` (iOS simulator x86_64)
- `aarch64-apple-darwin` (macOS ARM64)
- `x86_64-apple-darwin` (macOS x86_64)

## Troubleshooting

### Build Fails
```bash
# Clean everything and rebuild
make swift-clean
make swift-all
```

### XCFramework Issues
```bash
# Remove existing XCFramework and rebuild
rm -rf bindings/swift/LibSilver.xcframework
make swift-ffi
make swift-package
```

### Swift Package Issues
```bash
# Clean Swift build cache
cd bindings/swift
rm -rf .build/
swift build
```

## Output Files

After a successful build:

- **XCFramework**: `bindings/swift/LibSilver.xcframework`
- **Swift Bindings**: `bindings/swift/Sources/LibSilverFFI/*.swift`
- **Swift Package**: `bindings/swift/` (ready for distribution)

## Distribution

The `bindings/swift/` directory is a complete Swift package that can be:
1. Published to a Git repository
2. Added as a local Swift package
3. Distributed via Swift Package Manager

Example usage in client projects:
```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/YourOrg/libsilver-swift.git", from: "0.1.0")
]
```
