#!/bin/bash

# Build script for LibSilver Node.js bindings

set -e

echo "🔨 Building LibSilver Node.js bindings..."

# Navigate to the Node.js bindings directory
cd "$(dirname "$0")"

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf target/
rm -f *.node

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Build for current platform
echo "🏗️ Building for current platform..."
npm run build

# Run tests
echo "🧪 Running tests..."
npm test

# Run examples
echo "🚀 Running examples..."
node examples/nodejs-example.js

echo "✅ Build completed successfully!"
echo ""
echo "📋 Next steps:"
echo "  - Run 'npm run build:all' to build for all platforms"
echo "  - Run 'npm run prepublishOnly' to prepare for publishing"
echo "  - Run 'npm publish' to publish to npm registry"
