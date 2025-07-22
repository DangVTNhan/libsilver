/// <reference types="node" />

export * from "./native";
import {
  MlKem512KeyPairJs,
  MlKem768KeyPairJs,
  MlKem1024KeyPairJs,
  MlDsa44KeyPairJs,
  MlDsa65KeyPairJs,
  MlDsa87KeyPairJs,
  MlKem512EncapsulationJs,
  MlKem768EncapsulationJs,
  MlKem1024EncapsulationJs,
} from "./native";

export declare class Crypto {
  static encrypt(
    plaintext: Buffer,
    key: Buffer,
    aad?: Buffer | null,
    algorithm?: string
  ): Buffer;

  static encryptWithNonce(
    plaintext: Buffer,
    key: Buffer,
    nonce: Buffer,
    aad?: Buffer | null,
    algorithm?: string
  ): Buffer;

  static getNonceFromCiphertext(ciphertext: Buffer): Buffer;

  static decrypt(
    ciphertext: Buffer,
    key: Buffer,
    aad?: Buffer | null,
    algorithm?: string
  ): Buffer;

  static generateEncryptionKey(algorithm?: string): Buffer;

  static generateEncapsulationKey(
    algorithm?: string
  ): MlKem512KeyPairJs | MlKem768KeyPairJs | MlKem1024KeyPairJs;

  static encapsulate(
    publicKey: Buffer,
    algorithm?: string
  ):
    | MlKem512EncapsulationJs
    | MlKem768EncapsulationJs
    | MlKem1024EncapsulationJs;

  static decapsulate(
    ciphertext: Buffer,
    privateKey: Buffer,
    algorithm?: string
  ): Buffer;

  static generateSignatureKey(
    algorithm?: string
  ): MlDsa44KeyPairJs | MlDsa65KeyPairJs | MlDsa87KeyPairJs;

  static sign(message: Buffer, privateKey: Buffer, algorithm?: string): Buffer;

  static verify(
    message: Buffer,
    signature: Buffer,
    publicKey: Buffer,
    algorithm?: string
  ): boolean;

  static hash(data: Buffer, algorithm?: string): Buffer;
  static hashHex(data: Buffer, algorithm?: string): string;

  static hmac(key: Buffer, message: Buffer, algorithm?: string): Buffer;
  static verifyHmac(
    key: Buffer,
    message: Buffer,
    expectedMac: Buffer,
    algorithm?: string
  ): boolean;

  static derivePassword(
    password: string | Buffer,
    salt: Buffer,
    digestLength?: number,
    algorithm?: string
  ): Buffer;
}

/**
 * StreamEncryption - Stateful AES-256-GCM stream cipher with automatic nonce management
 *
 * This class provides a high-level wrapper around the StreamCipherJs native implementation,
 * offering stateful encryption/decryption with automatic nonce management and thread safety.
 *
 * Features:
 * - Automatic nonce increment for each operation
 * - Thread-safe operations using Arc<Mutex<>> internally
 * - AWS-LC-RS backend for high performance
 * - Zero-copy operations with BufferRef support
 * - Stateful design for streaming data processing
 */
export declare class StreamEncryption {
  /**
   * Create a new StreamEncryption instance
   * @param key - AES-256 key (must be exactly 32 bytes)
   */
  constructor(key: Buffer);

  /**
   * Generate a new AES-256 key for stream cipher use
   * @returns 32-byte AES-256 key
   */
  static generateKey(): Buffer;

  /**
   * Encrypt a chunk of data using the stream cipher
   *
   * This method automatically generates a unique nonce for each operation
   * by incrementing an internal counter. The returned ciphertext includes
   * the nonce prefix for decryption.
   *
   * @param plaintext - Data to encrypt
   * @returns Encrypted data with nonce prefix (nonce + ciphertext + tag)
   */
  encryptChunk(plaintext: Buffer): Buffer;

  /**
   * Decrypt a chunk of data using the stream cipher
   *
   * The ciphertext must include the nonce prefix as returned by encryptChunk.
   *
   * @param ciphertext - Encrypted data with nonce prefix (nonce + ciphertext + tag)
   * @returns Decrypted plaintext data
   */
  decryptChunk(ciphertext: Buffer): Buffer;

  /**
   * Reset the stream cipher state
   *
   * This generates a new base nonce and resets the nonce counter to 0.
   * Use this method when the nonce counter approaches overflow or when
   * starting a new encryption session.
   */
  reset(): void;

  /**
   * Get the current nonce counter value
   *
   * This can be used to monitor nonce usage and determine when to reset.
   * Consider resetting when the counter approaches the maximum value.
   *
   * @returns Current nonce counter value
   */
  getNonceCounter(): number;

  /**
   * Encrypt a chunk of data with additional authenticated data (AAD)
   *
   * This method performs authenticated encryption where the AAD is authenticated
   * but not encrypted. The returned ciphertext includes the nonce prefix for
   * decryption, similar to the standard encryptChunk method.
   *
   * @param plaintext - Data to encrypt
   * @param aad - Additional authenticated data (not encrypted, but authenticated)
   * @returns Encrypted data with nonce prefix (nonce + ciphertext + tag)
   */
  encryptChunkWithAad(plaintext: Buffer, aad: Buffer): Buffer;

  /**
   * Decrypt a chunk of data with additional authenticated data (AAD)
   *
   * This method performs authenticated decryption where the AAD is verified
   * along with the ciphertext. The ciphertext must include the nonce prefix
   * and authentication tag as returned by encryptChunkWithAad.
   *
   * @param ciphertext - Encrypted data with nonce prefix (nonce + ciphertext + tag)
   * @param aad - Additional authenticated data (same as used during encryption)
   * @returns Decrypted plaintext data
   */
  decryptChunkWithAad(ciphertext: Buffer, aad: Buffer): Buffer;
}

// Support default export for ES modules
declare const _default: typeof import("./native") & {
  Crypto: typeof Crypto;
  StreamEncryption: typeof StreamEncryption;
};
export default _default;
