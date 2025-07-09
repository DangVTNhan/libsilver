# Centralized Cryptography Library Implementation Plan

## Project Overview
Create a centralized Rust cryptography library (`libsilver`) that provides core cryptographic primitives and can be compiled for multiple target platforms through FFI bridges.

**Target Platforms:**
- Node.js (Electron desktop applications)
- Swift (iOS/macOS applications)
- Kotlin/Java (Android/JVM applications)

---

## Phase 1: Research & Technology Stack Selection

### 1.1 FFI/Bridge Technologies Analysis

#### Node.js Integration
**Recommended: NAPI-RS**
- **Pros**: Modern N-API bindings, excellent TypeScript support, active maintenance
- **Cons**: Steeper learning curve than alternatives
- **Alternative**: `neon` (older but stable)
- **Build Tool**: `@napi-rs/cli`

#### Swift Integration  
**Recommended: UniFFI**
- **Pros**: Mozilla-backed, excellent Swift bindings generation, mature ecosystem
- **Cons**: Some limitations with complex types
- **Alternative**: `swift-bridge` (more manual but flexible)
- **Build Tool**: `uniffi-bindgen`

#### Kotlin/Java Integration
**Recommended: UniFFI + JNI**
- **Pros**: UniFFI generates Kotlin bindings, handles JNI complexity
- **Cons**: Android-specific setup required
- **Alternative**: Direct `jni-rs` (more control, more complexity)
- **Build Tool**: `uniffi-bindgen` + Gradle integration

### 1.2 RustCrypto Crates Selection

#### Core Cryptographic Primitives
```toml
# Symmetric Encryption
aes = "0.8"
chacha20poly1305 = "0.10"

# Asymmetric Encryption
rsa = "0.9"
p256 = "0.13"  # ECDSA/ECDH with P-256
ed25519-dalek = "2.0"

# Hashing
sha2 = "0.10"
blake3 = "1.5"

# Key Derivation
argon2 = "0.5"
hkdf = "0.12"

# Random Number Generation
rand = "0.8"
getrandom = "0.2"

# Utilities
hex = "0.4"
base64 = "0.21"
zeroize = "1.7"
```

### 1.3 Cross-Compilation Targets

#### Required Rust Targets
```bash
# Desktop
x86_64-pc-windows-msvc
x86_64-apple-darwin
aarch64-apple-darwin
x86_64-unknown-linux-gnu

# Mobile
aarch64-apple-ios
aarch64-linux-android
armv7-linux-androideabi
i686-linux-android
x86_64-linux-android
```

---

## Phase 2: Architecture Design

### 2.1 Core Library Structure

```
libsilver/
├── src/
│   ├── lib.rs              # Main library entry point
│   ├── core/               # Core cryptographic implementations
│   │   ├── mod.rs
│   │   ├── symmetric.rs    # AES, ChaCha20-Poly1305
│   │   ├── asymmetric.rs   # RSA, ECDSA, Ed25519
│   │   ├── hashing.rs      # SHA-2, BLAKE3
│   │   ├── kdf.rs          # Argon2, HKDF
│   │   └── random.rs       # Secure random generation
│   ├── ffi/                # FFI interface layer
│   │   ├── mod.rs
│   │   ├── c_api.rs        # C-compatible API
│   │   └── types.rs        # FFI-safe type definitions
│   ├── bindings/           # Platform-specific bindings
│   │   ├── nodejs/         # Node.js NAPI bindings
│   │   ├── swift/          # Swift/iOS bindings
│   │   └── kotlin/         # Kotlin/Android bindings
│   └── error.rs            # Unified error handling
├── uniffi/                 # UniFFI configuration
│   └── libsilver.udl        # Interface definition
├── bindings-nodejs/        # Generated Node.js bindings
├── bindings-swift/         # Generated Swift bindings
├── bindings-kotlin/        # Generated Kotlin bindings
└── examples/               # Platform-specific examples
```

### 2.2 API Design Principles

#### Core API Interface
```rust
// Unified error type for all platforms
pub enum CryptoError {
    InvalidInput,
    EncryptionFailed,
    DecryptionFailed,
    KeyGenerationFailed,
    InvalidKey,
}

// Core traits for cryptographic operations
pub trait SymmetricCipher {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub trait AsymmetricCipher {
    fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError>;
    fn encrypt(&self, plaintext: &[u8], public_key: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&self, ciphertext: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
```

### 2.3 Platform-Specific API Adaptations

#### Node.js API (TypeScript)
```typescript
export interface CryptoResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export class SymmetricCrypto {
  static encryptAES(plaintext: Buffer, key: Buffer): CryptoResult<Buffer>;
  static decryptAES(ciphertext: Buffer, key: Buffer): CryptoResult<Buffer>;
}
```

#### Swift API
```swift
public enum CryptoError: Error {
    case invalidInput
    case encryptionFailed
    case decryptionFailed
}

public class SymmetricCrypto {
    public static func encryptAES(plaintext: Data, key: Data) throws -> Data
    public static func decryptAES(ciphertext: Data, key: Data) throws -> Data
}
```

#### Kotlin API
```kotlin
sealed class CryptoResult<out T> {
    data class Success<T>(val data: T) : CryptoResult<T>()
    data class Error(val message: String) : CryptoResult<Nothing>()
}

class SymmetricCrypto {
    companion object {
        fun encryptAES(plaintext: ByteArray, key: ByteArray): CryptoResult<ByteArray>
        fun decryptAES(ciphertext: ByteArray, key: ByteArray): CryptoResult<ByteArray>
    }
}
```

---

## Phase 3: Implementation Steps

### 3.1 Core Library Setup

#### Step 1: Initialize Rust Project Structure
```bash
# Update Cargo.toml with workspace configuration
# Add core cryptographic dependencies
# Set up conditional compilation features
```

#### Step 2: Implement Core Cryptographic Modules
1. **Symmetric Encryption Module** (`src/core/symmetric.rs`)
   - AES-256-GCM implementation
   - ChaCha20-Poly1305 implementation
   - Key generation utilities

2. **Asymmetric Encryption Module** (`src/core/asymmetric.rs`)
   - RSA-OAEP implementation
   - ECDSA with P-256 curve
   - Ed25519 signatures

3. **Hashing Module** (`src/core/hashing.rs`)
   - SHA-256/SHA-512 implementations
   - BLAKE3 hashing
   - HMAC implementations

4. **Key Derivation Module** (`src/core/kdf.rs`)
   - Argon2 password hashing
   - HKDF key derivation
   - PBKDF2 implementation

#### Step 3: Create FFI Layer
1. **C-Compatible API** (`src/ffi/c_api.rs`)
   - Export functions with C calling convention
   - Handle memory management safely
   - Convert Rust types to C-compatible types

2. **FFI-Safe Types** (`src/ffi/types.rs`)
   - Define repr(C) structs
   - Handle string and byte array conversions
   - Implement proper error handling

### 3.2 Node.js Integration

#### Step 1: Setup NAPI-RS
```bash
npm init napi --name libsilver-node
# Configure package.json for cross-platform builds
# Setup TypeScript definitions
```

#### Step 2: Implement Node.js Bindings
1. **Create NAPI Wrapper** (`src/bindings/nodejs/mod.rs`)
   - Use `#[napi]` macros for function exports
   - Handle JavaScript type conversions
   - Implement async operations where beneficial

2. **TypeScript Definitions**
   - Generate `.d.ts` files automatically
   - Provide comprehensive type safety
   - Document all exported functions

#### Step 3: Build Configuration
```toml
[package.metadata.napi]
name = "libsilver"
triples = [
  "x86_64-pc-windows-msvc",
  "x86_64-apple-darwin",
  "aarch64-apple-darwin",
  "x86_64-unknown-linux-gnu"
]
```

### 3.3 Swift Integration

#### Step 1: Setup UniFFI
```bash
cargo install uniffi-bindgen
# Create uniffi/libsilver.udl interface definition
# Configure Cargo.toml for UniFFI
```

#### Step 2: Define UniFFI Interface
```udl
// uniffi/libsilver.udl
namespace libsilver {
    [Throws=CryptoError]
    bytes encrypt_aes(bytes plaintext, bytes key);
    
    [Throws=CryptoError]
    bytes decrypt_aes(bytes ciphertext, bytes key);
};

[Error]
enum CryptoError {
    "InvalidInput",
    "EncryptionFailed",
    "DecryptionFailed"
};
```

#### Step 3: Generate Swift Bindings
```bash
uniffi-bindgen generate src/libsilver.udl --language swift --out-dir bindings-swift/
```

#### Step 4: iOS/macOS Integration
1. **Create XCFramework**
   - Build for iOS simulator and device
   - Build for macOS Intel and Apple Silicon
   - Package into universal XCFramework

2. **Swift Package Manager Integration**
   - Create Package.swift
   - Configure binary targets
   - Set up proper dependencies

### 3.4 Kotlin/Java Integration

#### Step 1: Setup UniFFI for Kotlin
```bash
uniffi-bindgen generate src/libsilver.udl --language kotlin --out-dir bindings-kotlin/
```

#### Step 2: Android Integration
1. **JNI Library Setup**
   - Configure Android NDK builds
   - Set up Gradle build scripts
   - Handle different Android architectures

2. **Kotlin Bindings Integration**
   - Package generated Kotlin files
   - Create Android AAR library
   - Set up proper JNI loading

#### Step 3: JVM Integration
1. **Desktop JVM Support**
   - Build native libraries for desktop platforms
   - Create JAR with native dependencies
   - Set up proper library loading mechanism

---

## Phase 4: Build System & Toolchain

### 4.1 Cargo Configuration

#### Cargo.toml Features
```toml
[features]
default = ["std"]
std = []
nodejs = ["napi", "napi-derive"]
uniffi = ["dep:uniffi"]
all-platforms = ["nodejs", "uniffi"]

[dependencies]
# Core crypto dependencies
aes = "0.8"
chacha20poly1305 = "0.10"
rsa = "0.9"
p256 = "0.13"
ed25519-dalek = "2.0"
sha2 = "0.10"
blake3 = "1.5"
argon2 = "0.5"
hkdf = "0.12"
rand = "0.8"
getrandom = "0.2"
hex = "0.4"
base64 = "0.21"
zeroize = "1.7"

# FFI dependencies
napi = { version = "2.0", optional = true }
napi-derive = { version = "2.0", optional = true }
uniffi = { version = "0.25", optional = true }

[lib]
crate-type = ["cdylib", "rlib"]
```

### 4.2 Cross-Compilation Setup

#### Install Required Targets
```bash
# Desktop targets
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin
rustup target add x86_64-unknown-linux-gnu

# Mobile targets
rustup target add aarch64-apple-ios
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android
```

#### Configure Cross-Compilation Tools
```bash
# Install cross-compilation helper
cargo install cross

# Install Android NDK (for Android targets)
# Install Xcode (for iOS/macOS targets)
# Install Windows SDK (for Windows targets)
```

### 4.3 Build Scripts

#### Platform-Specific Build Scripts

##### Node.js Build Script
```bash
#!/bin/bash
# scripts/build-nodejs.sh
npm run build:all
npm run test
```

##### Swift XCFramework Build Script
```bash
#!/bin/bash
# scripts/build-xcframework.sh

# Build for iOS device
cargo build --release --target aarch64-apple-ios

# Build for iOS simulator
cargo build --release --target x86_64-apple-ios

# Build for macOS
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin

# Create XCFramework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/liblibsiver.a \
  -library target/x86_64-apple-ios/release/liblibsiver.a \
  -library target/x86_64-apple-darwin/release/liblibsiver.a \
  -library target/aarch64-apple-darwin/release/liblibsiver.a \
  -output LibSiver.xcframework
```

##### Android/JVM Build Script
```bash
#!/bin/bash
# scripts/build-android.sh

# Android targets
cross build --release --target aarch64-linux-android
cross build --release --target armv7-linux-androideabi
cross build --release --target i686-linux-android
cross build --release --target x86_64-linux-android

# Copy to Android jniLibs structure
mkdir -p android-libs/arm64-v8a
mkdir -p android-libs/armeabi-v7a
mkdir -p android-libs/x86
mkdir -p android-libs/x86_64

cp target/aarch64-linux-android/release/liblibsiver.so android-libs/arm64-v8a/
cp target/armv7-linux-androideabi/release/liblibsiver.so android-libs/armeabi-v7a/
cp target/i686-linux-android/release/liblibsiver.so android-libs/x86/
cp target/x86_64-linux-android/release/liblibsiver.so android-libs/x86_64/
```

##### JVM Build Script
```bash
#!/bin/bash
# scripts/build-jvm.sh

# Desktop JVM targets
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin

# Copy to JVM resources structure
mkdir -p jvm-libs/linux-x86-64
mkdir -p jvm-libs/windows-x86-64
mkdir -p jvm-libs/darwin-x86-64
mkdir -p jvm-libs/darwin-aarch64

cp target/x86_64-unknown-linux-gnu/release/liblibsiver.so jvm-libs/linux-x86-64/
cp target/x86_64-pc-windows-msvc/release/libsiver.dll jvm-libs/windows-x86-64/
cp target/x86_64-apple-darwin/release/liblibsiver.dylib jvm-libs/darwin-x86-64/
cp target/aarch64-apple-darwin/release/liblibsiver.dylib jvm-libs/darwin-aarch64/
```

---

## Phase 5: Testing Strategy

### 5.1 Unit Testing
- **Core Library Tests**: Test all cryptographic operations
- **FFI Layer Tests**: Verify C API compatibility
- **Memory Safety Tests**: Ensure no memory leaks in FFI

### 5.2 Integration Testing
- **Node.js Tests**: Jest/Mocha test suites
- **Swift Tests**: XCTest framework
- **Kotlin Tests**: JUnit/Kotest framework

### 5.3 Cross-Platform Testing
- **CI/CD Pipeline**: GitHub Actions for all platforms
- **Performance Benchmarks**: Compare with native implementations
- **Security Audits**: Regular dependency and code audits

### 5.4 Example Applications
- **Electron Demo**: Desktop encryption tool
- **iOS Demo**: Mobile encryption app
- **Android Demo**: Mobile encryption app

---

## Phase 6: CI/CD & Distribution

### 6.1 GitLab CI/CD Pipeline
```yaml
# .gitlab-ci.yml
stages:
  - test
  - build
  - package
  - publish

variables:
  CARGO_HOME: $CI_PROJECT_DIR/.cargo

cache:
  paths:
    - .cargo/
    - target/

test:
  stage: test
  image: rust:latest
  script:
    - rustup component add clippy rustfmt
    - cargo fmt -- --check
    - cargo clippy -- -D warnings
    - cargo test --all-features
  parallel:
    matrix:
      - RUST_TARGET: [x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc, x86_64-apple-darwin]

build-nodejs:
  stage: build
  image: node:18
  before_script:
    - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    - source ~/.cargo/env
    - npm install -g @napi-rs/cli
  script:
    - npm install
    - npm run build:all
  artifacts:
    paths:
      - npm/
    expire_in: 1 hour

build-swift:
  stage: build
  tags:
    - macos
  script:
    - cargo install uniffi-bindgen
    - uniffi-bindgen generate src/libsiver.udl --language swift --out-dir bindings-swift/
    - ./scripts/build-xcframework.sh
  artifacts:
    paths:
      - bindings-swift/
      - LibSiver.xcframework/
    expire_in: 1 hour

build-kotlin:
  stage: build
  image: rust:latest
  before_script:
    - apt-get update && apt-get install -y openjdk-11-jdk
    - cargo install cross uniffi-bindgen
  script:
    - uniffi-bindgen generate src/libsiver.udl --language kotlin --out-dir bindings-kotlin/
    - ./scripts/build-android.sh
    - ./scripts/build-jvm.sh
  artifacts:
    paths:
      - bindings-kotlin/
      - android-libs/
      - jvm-libs/
    expire_in: 1 hour

package-npm:
  stage: package
  image: node:18
  dependencies:
    - build-nodejs
  script:
    - cd npm && npm pack
  artifacts:
    paths:
      - npm/*.tgz

package-swift:
  stage: package
  tags:
    - macos
  dependencies:
    - build-swift
  script:
    - ./scripts/package-swift.sh
  artifacts:
    paths:
      - LibSiver-Swift.zip

package-kotlin:
  stage: package
  image: openjdk:11
  dependencies:
    - build-kotlin
  script:
    - ./scripts/package-kotlin.sh
  artifacts:
    paths:
      - libsiver-kotlin.aar
      - libsiver-jvm.jar

publish-npm:
  stage: publish
  image: node:18
  dependencies:
    - package-npm
  script:
    - echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc
    - cd npm && npm publish
  only:
    - tags

publish-swift:
  stage: publish
  tags:
    - macos
  dependencies:
    - package-swift
  script:
    - ./scripts/publish-swift.sh
  only:
    - tags

publish-kotlin:
  stage: publish
  image: openjdk:11
  dependencies:
    - package-kotlin
  script:
    - ./scripts/publish-maven.sh
  only:
    - tags
```

### 6.2 Distribution Strategy & Package Management

#### 6.2.1 Node.js Distribution (Similar to npm)
```json
// package.json
{
  "name": "@yourorg/libsiver",
  "version": "1.0.0",
  "description": "Cross-platform cryptography library",
  "main": "index.js",
  "types": "index.d.ts",
  "napi": {
    "name": "libsiver",
    "triples": {
      "defaults": true,
      "additional": [
        "x86_64-pc-windows-msvc",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-unknown-linux-gnu"
      ]
    }
  },
  "files": ["index.js", "index.d.ts", "*.node"],
  "scripts": {
    "build": "napi build --platform --release",
    "build:all": "napi build --platform --release --target x86_64-pc-windows-msvc --target x86_64-apple-darwin --target aarch64-apple-darwin --target x86_64-unknown-linux-gnu"
  }
}
```

**Installation**: `npm install @yourorg/libsiver`

#### 6.2.2 Swift Distribution (Swift Package Manager)
```swift
// Package.swift
// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "LibSiver",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "LibSiver",
            targets: ["LibSiver"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "LibSiverFFI",
            url: "https://gitlab.com/yourorg/libsiver/-/releases/v1.0.0/downloads/LibSiver.xcframework.zip",
            checksum: "your-checksum-here"
        ),
        .target(
            name: "LibSiver",
            dependencies: ["LibSiverFFI"],
            path: "bindings-swift"
        ),
        .testTarget(
            name: "LibSiverTests",
            dependencies: ["LibSiver"]
        ),
    ]
)
```

**Installation**: Add to Xcode project or Package.swift:
```swift
dependencies: [
    .package(url: "https://gitlab.com/yourorg/libsiver-swift.git", from: "1.0.0")
]
```

#### 6.2.3 Kotlin/Android Distribution (Maven/Gradle)

**Android AAR Distribution**:
```gradle
// build.gradle (Module: app)
dependencies {
    implementation 'com.yourorg:libsiver-android:1.0.0'
}
```

**Maven Repository Setup**:
```xml
<!-- pom.xml for Maven Central -->
<project>
    <groupId>com.yourorg</groupId>
    <artifactId>libsiver-kotlin</artifactId>
    <version>1.0.0</version>
    <packaging>aar</packaging>

    <name>LibSiver Kotlin</name>
    <description>Cross-platform cryptography library for Kotlin/Android</description>
    <url>https://gitlab.com/yourorg/libsiver</url>

    <licenses>
        <license>
            <name>MIT License</name>
            <url>https://opensource.org/licenses/MIT</url>
        </license>
    </licenses>
</project>
```

**JVM Distribution**:
```gradle
// build.gradle for JVM projects
dependencies {
    implementation 'com.yourorg:libsiver-jvm:1.0.0'
}
```

#### 6.2.4 Distribution Comparison with npm

| Platform | Package Manager | Registry | Installation Command |
|----------|----------------|----------|---------------------|
| **Node.js** | npm/yarn/pnpm | npmjs.org | `npm install @yourorg/libsiver` |
| **Swift** | Swift Package Manager | Git-based | Add to Package.swift dependencies |
| **Kotlin/Android** | Gradle/Maven | Maven Central | `implementation 'com.yourorg:libsiver-android:1.0.0'` |
| **JVM** | Gradle/Maven | Maven Central | `implementation 'com.yourorg:libsiver-jvm:1.0.0'` |

**Key Differences from npm**:
- **Swift**: Uses Git repositories + binary releases (similar to npm but Git-based)
- **Kotlin/Android**: Uses Maven Central (more complex publishing process than npm)
- **All platforms**: Support automatic dependency resolution like npm

### 6.3 Automated Publishing Pipeline

#### 6.3.1 Release Script
```bash
#!/bin/bash
# scripts/release.sh

VERSION=$1
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

# Update version in all package files
sed -i "s/version = \".*\"/version = \"$VERSION\"/" Cargo.toml
sed -i "s/\"version\": \".*\"/\"version\": \"$VERSION\"/" package.json
sed -i "s/version: \".*\"/version: \"$VERSION\"/" Package.swift

# Commit and tag
git add .
git commit -m "Release v$VERSION"
git tag "v$VERSION"
git push origin main --tags

echo "Release v$VERSION created. GitLab CI will handle publishing."
```

#### 6.3.2 Registry Configuration
```bash
# GitLab CI Variables (set in GitLab UI)
NPM_TOKEN=your-npm-token
MAVEN_USERNAME=your-maven-username
MAVEN_PASSWORD=your-maven-password
APPLE_DEVELOPER_ID=your-apple-id
```

---

## Phase 7: Security Considerations

### 7.1 Memory Safety
- Use `zeroize` for sensitive data cleanup
- Implement proper memory management in FFI
- Regular security audits with `cargo audit`

### 7.2 Cryptographic Best Practices
- Use authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- Implement proper key derivation
- Use secure random number generation
- Follow OWASP cryptographic guidelines

### 7.3 Supply Chain Security
- Pin dependency versions
- Regular dependency updates
- Automated vulnerability scanning
- Code signing for distributed binaries

---