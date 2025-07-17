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

// Support default export for ES modules
declare const _default: typeof import("./native") & { Crypto: typeof Crypto };
export default _default;
