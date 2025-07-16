export * from "./native";

export declare class Crypto {
  encrypt(
    plaintext: Buffer,
    key: Buffer,
    aad?: Buffer | null,
    algorithm?: string | null
  ): Buffer;
  decrypt(
    ciphertext: Buffer,
    key: Buffer,
    aad?: Buffer | null,
    algorithm?: string | null
  ): Buffer;
  generateEncryptionKey(algorithm?: string | null): Buffer;
  generateEncapsulationKey(algorithm?: string | null): Buffer;
  encapsulate(publicKey: Buffer, algorithm?: string | null): Buffer;
  decapsulate(
    ciphertext: Buffer,
    privateKey: Buffer,
    algorithm?: string | null
  ): Buffer;
  generateSignatureKey(algorithm?: string | null): Buffer;
  sign(message: Buffer, privateKey: Buffer, algorithm?: string | null): Buffer;
  verify(
    message: Buffer,
    signature: Buffer,
    publicKey: Buffer,
    algorithm?: string | null
  ): boolean;

  hash(data: Buffer, algorithm?: string | null): Buffer;
  hashHex(data: Buffer, algorithm?: string | null): string;

  hmac(key: Buffer, message: Buffer, algorithm?: string | null): Buffer;
  verifyHmac(
    key: Buffer,
    message: Buffer,
    expectedMac: Buffer,
    algorithm?: string | null
  ): boolean;

  derivePassword(
    password: string,
    salt: Buffer,
    digestLength?: number | null,
    algorithm?: string | null
  ): Buffer;
}
