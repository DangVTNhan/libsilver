import XCTest
@testable import LibSilver

final class LibSilverTests: XCTestCase {
    
    override func setUpWithError() throws {
        // Initialize LibSilver before running tests
        LibSilver.initialize()
    }
    
    func testLibraryVersion() throws {
        let version = LibSilver.version
        XCTAssertFalse(version.isEmpty, "Version should not be empty")
        print("LibSilver version: \(version)")
    }
    
    func testAESKeyGeneration() throws {
        let key = try AES.generateKey()
        XCTAssertEqual(key.count, 32, "AES-256 key should be 32 bytes")
    }
    
    func testAESEncryptionDecryption() throws {
        let plaintext = "Hello, LibSilver!".data(using: .utf8)!
        let key = try AES.generateKey()
        
        // Encrypt
        let (ciphertext, nonce) = try AES.encrypt(plaintext, key: key)
        XCTAssertNotEqual(ciphertext, plaintext, "Ciphertext should be different from plaintext")
        XCTAssertEqual(nonce.count, 12, "AES-GCM nonce should be 12 bytes")
        
        // Decrypt
        let decrypted = try AES.decrypt(ciphertext, nonce: nonce, key: key)
        XCTAssertEqual(decrypted, plaintext, "Decrypted text should match original plaintext")
    }
    
    func testEd25519KeyGeneration() throws {
        let keyPair = try Ed25519.generateKeyPair()
        XCTAssertEqual(keyPair.publicKey.count, 32, "Ed25519 public key should be 32 bytes")
        XCTAssertEqual(keyPair.privateKey.count, 32, "Ed25519 private key should be 32 bytes")
    }
    
    func testEd25519SignatureVerification() throws {
        let message = "Test message for signing".data(using: .utf8)!
        let keyPair = try Ed25519.generateKeyPair()
        
        // Sign
        let signature = try Ed25519.sign(message, privateKey: keyPair.privateKey)
        XCTAssertEqual(signature.count, 64, "Ed25519 signature should be 64 bytes")
        
        // Verify
        let isValid = try Ed25519.verify(message, signature: signature, publicKey: keyPair.publicKey)
        XCTAssertTrue(isValid, "Signature should be valid")
        
        // Test with wrong message
        let wrongMessage = "Wrong message".data(using: .utf8)!
        let isInvalid = try Ed25519.verify(wrongMessage, signature: signature, publicKey: keyPair.publicKey)
        XCTAssertFalse(isInvalid, "Signature should be invalid for wrong message")
    }
    
    func testSHA256Hashing() throws {
        let data = "Hello, World!".data(using: .utf8)!
        let hash = try Hash.sha256(data)
        XCTAssertEqual(hash.count, 32, "SHA-256 hash should be 32 bytes")
        
        // Test hex output
        let hexHash = try Hash.sha256Hex(data)
        XCTAssertFalse(hexHash.isEmpty, "Hex hash should not be empty")
        XCTAssertEqual(hexHash.count, 64, "Hex hash should be 64 characters")
    }
    
    func testSecureRandomGeneration() throws {
        let randomBytes1 = try SecureRandom.generateBytes(32)
        let randomBytes2 = try SecureRandom.generateBytes(32)
        
        XCTAssertEqual(randomBytes1.count, 32, "Should generate 32 bytes")
        XCTAssertEqual(randomBytes2.count, 32, "Should generate 32 bytes")
        XCTAssertNotEqual(randomBytes1, randomBytes2, "Random bytes should be different")
    }
    
    func testPerformanceAESEncryption() throws {
        let plaintext = Data(repeating: 0x42, count: 1024) // 1KB of data
        let key = try AES.generateKey()
        
        measure {
            do {
                let _ = try AES.encrypt(plaintext, key: key)
            } catch {
                XCTFail("Encryption failed: \(error)")
            }
        }
    }
    
    func testPerformanceEd25519Signing() throws {
        let message = Data(repeating: 0x42, count: 1024) // 1KB of data
        let keyPair = try Ed25519.generateKeyPair()
        
        measure {
            do {
                let _ = try Ed25519.sign(message, privateKey: keyPair.privateKey)
            } catch {
                XCTFail("Signing failed: \(error)")
            }
        }
    }
    
    func testPerformanceSHA256() throws {
        let data = Data(repeating: 0x42, count: 1024 * 1024) // 1MB of data
        
        measure {
            do {
                let _ = try Hash.sha256(data)
            } catch {
                XCTFail("Hashing failed: \(error)")
            }
        }
    }
}
