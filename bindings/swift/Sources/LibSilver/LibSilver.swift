import Foundation
import LibSilverFFI

// MARK: - LibSilver Swift Bindings

/// Main LibSilver module for Swift
///
/// This library provides a Swift-friendly interface to the LibSilver Rust cryptography library,
/// offering both classical and post-quantum cryptographic operations.
public final class LibSilver {

    /// Initialize the LibSilver library
    /// Call this once before using any cryptographic functions
    public static func initialize() {
        LibSilverFFI.initialize()
    }

    /// Get the library version
    public static var version: String {
        return getVersion()
    }
}

// MARK: - Symmetric Encryption

/// AES-256-GCM symmetric encryption
public struct AES {

    /// Generate a new AES-256 key
    public static func generateKey() throws -> Data {
        do {
            let key = try generateAesKey()
            return Data(key.key)
        } catch let error as CryptoError {
            throw LibSilverError(from: error)
        }
    }

    /// Encrypt data using AES-256-GCM
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - key: The AES key
    /// - Returns: A tuple containing the ciphertext and nonce
    public static func encrypt(_ plaintext: Data, key: Data) throws -> (
        ciphertext: Data, nonce: Data
    ) {
        do {
            let aesKey = AesKey(key: key)
            let result = try encryptAes(plaintext: plaintext, key: aesKey)
            return (Data(result.ciphertext), Data(result.nonce))
        } catch let error as CryptoError {
            throw LibSilverError(from: error)
        }
    }

    /// Decrypt data using AES-256-GCM
    /// - Parameters:
    ///   - ciphertext: The encrypted data
    ///   - nonce: The nonce used for encryption
    ///   - key: The AES key
    /// - Returns: The decrypted plaintext
    public static func decrypt(_ ciphertext: Data, nonce: Data, key: Data) throws -> Data {
        do {
            let aesKey = AesKey(key: key)
            let plaintext = try decryptAes(ciphertext: ciphertext, nonce: nonce, key: aesKey)
            return plaintext
        } catch let error as CryptoError {
            throw LibSilverError(from: error)
        }
    }
}

// MARK: - Digital Signatures

/// Ed25519 digital signatures
public struct Ed25519 {

    /// Ed25519 key pair
    public struct KeyPair {
        public let publicKey: Data
        public let privateKey: Data

        internal init(from ffiKeyPair: LibSilverFFI.Ed25519KeyPair) {
            self.publicKey = Data(ffiKeyPair.publicKey)
            self.privateKey = Data(ffiKeyPair.privateKey)
        }
    }

    /// Generate a new Ed25519 key pair
    public static func generateKeyPair() throws -> KeyPair {
        do {
            let keyPair = try generateEd25519Keypair()
            return KeyPair(from: keyPair)
        } catch let error as CryptoError {
            throw LibSilverError(from: error)
        }
    }

    /// Sign a message using Ed25519
    /// - Parameters:
    ///   - message: The message to sign
    ///   - privateKey: The private key for signing
    /// - Returns: The signature
    public static func sign(_ message: Data, privateKey: Data) throws -> Data {
        do {
            return try signEd25519(message: message, privateKey: privateKey)
        } catch let error as CryptoError {
            throw LibSilverError(from: error)
        }
    }

    /// Verify an Ed25519 signature
    /// - Parameters:
    ///   - message: The original message
    ///   - signature: The signature to verify
    ///   - publicKey: The public key for verification
    /// - Returns: True if the signature is valid
    public static func verify(_ message: Data, signature: Data, publicKey: Data) throws -> Bool {
        do {
            return try verifyEd25519(message: message, signature: signature, publicKey: publicKey)
        } catch let error as CryptoError {
            throw LibSilverError(from: error)
        }
    }
}

// MARK: - Cryptographic Hashing

/// Cryptographic hash functions
public struct Hash {

    /// Compute SHA-256 hash
    public static func sha256(_ data: Data) throws -> Data {
        do {
            return try LibSilverFFI.sha256(data: data)
        } catch let error as CryptoError {
            throw LibSilverError(from: error)
        }
    }

    /// Compute SHA-256 hash and return as hex string
    public static func sha256Hex(_ data: Data) throws -> String {
        do {
            return try LibSilverFFI.sha256Hex(data: data)
        } catch let error as CryptoError {
            throw LibSilverError(from: error)
        }
    }
}

// MARK: - Secure Random Generation

/// Secure random number generation
public struct SecureRandom {

    /// Generate cryptographically secure random bytes
    /// - Parameter length: Number of bytes to generate
    /// - Returns: Random bytes
    public static func generateBytes(_ length: Int) throws -> Data {
        do {
            return try generateRandomBytes(length: UInt32(length))
        } catch let error as CryptoError {
            throw LibSilverError(from: error)
        }
    }
}

// MARK: - Error Handling

/// Swift-native error type for LibSilver operations
public enum LibSilverError: Error, LocalizedError {
    case invalidInput(String)
    case cryptographicError(String)
    case keyGenerationError(String)
    case encryptionError(String)
    case decryptionError(String)
    case signatureError(String)
    case verificationError(String)
    case hashError(String)
    case kdfError(String)
    case randomError(String)

    public var errorDescription: String? {
        switch self {
        case .invalidInput(let message):
            return "Invalid input: \(message)"
        case .cryptographicError(let message):
            return "Cryptographic error: \(message)"
        case .keyGenerationError(let message):
            return "Key generation error: \(message)"
        case .encryptionError(let message):
            return "Encryption error: \(message)"
        case .decryptionError(let message):
            return "Decryption error: \(message)"
        case .signatureError(let message):
            return "Signature error: \(message)"
        case .verificationError(let message):
            return "Verification error: \(message)"
        case .hashError(let message):
            return "Hash error: \(message)"
        case .kdfError(let message):
            return "Key derivation error: \(message)"
        case .randomError(let message):
            return "Random generation error: \(message)"
        }
    }
}

extension LibSilverError {
    init(from cryptoError: CryptoError) {
        switch cryptoError {
        case .InvalidInput(let message):
            self = .invalidInput(message)
        case .CryptographicError(let message):
            self = .cryptographicError(message)
        case .KeyGenerationError(let message):
            self = .keyGenerationError(message)
        case .EncryptionError(let message):
            self = .encryptionError(message)
        case .DecryptionError(let message):
            self = .decryptionError(message)
        case .SignatureError(let message):
            self = .signatureError(message)
        case .VerificationError(let message):
            self = .verificationError(message)
        case .HashError(let message):
            self = .hashError(message)
        case .KdfError(let message):
            self = .kdfError(message)
        case .RandomError(let message):
            self = .randomError(message)
        }
    }
}
