# Building LibSilver Node.js Bindings

This document describes how to build the Node.js bindings for LibSilver across different platforms.

## Prerequisites

### macOS (for cross-compilation)

1. **Install Rust and required targets:**
   ```bash
   # Install Rust if not already installed
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # Add required targets
   rustup target add aarch64-apple-darwin
   rustup target add x86_64-apple-darwin
   rustup target add x86_64-pc-windows-msvc
   ```

2. **Install cross-compilation tools:**
   ```bash
   # Install cargo-xwin for Windows cross-compilation
   cargo install cargo-xwin
   
   # Install LLVM for Windows linking
   brew install llvm
   ```

3. **Install Node.js dependencies:**
   ```bash
   npm install
   ```

## Building

### Build for all supported platforms (macOS + Windows)
```bash
npm run build:all
```

This will create four binaries:
- `libsilver.darwin-arm64.node` - macOS ARM64 (M1/M2 Macs)
- `libsilver.darwin-x64.node` - macOS Intel x64
- `libsilver.win32-x64-msvc.node` - Windows x64
- `libsilver.win32-arm64-msvc.node` - Windows ARM64

### Build for specific platforms

#### macOS ARM64 only
```bash
npx napi build --platform --release --target aarch64-apple-darwin
```

#### macOS Intel only
```bash
npx napi build --platform --release --target x86_64-apple-darwin
```

#### Windows x64 only
```bash
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
npx napi build --platform --release --target x86_64-pc-windows-msvc
```

#### Windows ARM64 only
```bash
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
npx napi build --platform --release --target aarch64-pc-windows-msvc
```

### Development builds
```bash
npm run build:debug
```

## Testing

```bash
npm test
npm run example
```

## Cleaning

```bash
npm run clean
```

## Platform Support

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| macOS | ARM64 (M1/M2) | ✅ | Native compilation |
| macOS | Intel x64 | ✅ | Cross-compilation from ARM64 |
| Windows | x64 | ✅ | Cross-compilation using cargo-xwin |
| Windows | ARM64 | ✅ | Cross-compilation using cargo-xwin |
| Linux | x64 | ⚠️ | Requires CI/CD setup |
| Linux | ARM64 | ⚠️ | Requires CI/CD setup |

## Troubleshooting

### Windows Cross-compilation Issues

If you encounter linking errors when building for Windows:

1. Ensure LLVM is installed and in PATH:
   ```bash
   brew install llvm
   export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
   ```

2. Verify cargo-xwin is installed:
   ```bash
   cargo install cargo-xwin
   ```

3. Check that the Windows target is installed:
   ```bash
   rustup target list --installed | grep windows
   ```

### macOS Cross-compilation Issues

If you encounter issues building for different macOS architectures:

1. Ensure both targets are installed:
   ```bash
   rustup target add aarch64-apple-darwin x86_64-apple-darwin
   ```

2. Check Xcode command line tools are installed:
   ```bash
   xcode-select --install
   ```

## Linux Support

Linux cross-compilation from macOS requires additional setup and is best handled through CI/CD. The main challenges are:

1. **Node.js NAPI symbols**: Cross-compilation requires Node.js headers and NAPI symbols to be available in the target environment
2. **Docker dependencies**: Using `cross` requires Docker and specific container images
3. **Linking issues**: NAPI modules need to link against Node.js runtime libraries

### Recommended approach for Linux support:

1. **GitHub Actions CI/CD**: Set up automated builds using GitHub Actions with Linux runners
2. **Native compilation**: Build on actual Linux machines rather than cross-compilation
3. **Docker builds**: Use official Node.js Docker images for consistent builds

Example GitHub Actions workflow for Linux builds:
```yaml
- name: Build Linux x64
  run: npm run build
  env:
    TARGET: x86_64-unknown-linux-gnu

- name: Build Linux ARM64
  run: npm run build
  env:
    TARGET: aarch64-unknown-linux-gnu
```

## Future Enhancements

- Add Linux CI/CD builds using GitHub Actions
- Add automated platform-specific package publishing
- Add support for additional platforms (FreeBSD, etc.)
