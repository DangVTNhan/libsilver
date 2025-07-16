# StealthVault LibSilver - Private Installation Guide

This is a private GitLab package for the StealthVault LibSilver cryptography library.

## Installation

To install this package in your Node.js project, run:

```bash
npm install https://gitlab.silvertiger.tech/stealth-vault/stealthvault-libsilver.git
```

Or add it to your `package.json`:

```json
{
  "dependencies": {
    "stealthvault-libsilver": "git+https://gitlab.silvertiger.tech/stealth-vault/stealthvault-libsilver.git"
  }
}
```

## Usage

After installation, you can import and use the library:

```javascript
const libsilver = require('stealthvault-libsilver');

// Example usage
const { aes256GcmEncrypt, aes256GcmDecrypt } = libsilver;

// Your cryptographic operations here
```

## Requirements

- Node.js >= 14
- Access to the private GitLab repository

## Platform Support

This package includes pre-built binaries for:
- macOS (ARM64 and x64)
- Windows (ARM64 and x64)

## Development

For development and building from source, see the main README.md file.

## License

MIT License - see LICENSE file for details.
