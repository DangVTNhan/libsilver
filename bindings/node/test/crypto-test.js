const { Crypto } = require("../index.js");

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

function testCrypto() {
  console.log("Testing Crypto...");

  // Test AES-256-GCM
  const aesKey = Crypto.generateEncryptionKey();
  assert(aesKey.length === 32, "AES key should be 32 bytes");

  const plaintext = Buffer.from("Hello, World!", "utf8");
  const ciphertext = Crypto.encrypt(plaintext, aesKey);
  const decrypted = Crypto.decrypt(ciphertext, aesKey);

  assert(
    plaintext.equals(decrypted),
    "AES decryption should match original plaintext"
  );
  console.log("✓ AES-256-GCM encryption/decryption works");

  // Test ChaCha20-Poly1305
  const chachaKey = Crypto.generateEncryptionKey("chacha20-poly1305");
  assert(chachaKey.length === 32, "ChaCha20 key should be 32 bytes");

  const ciphertext2 = Crypto.encrypt(
    plaintext,
    chachaKey,
    null,
    "chacha20-poly1305"
  );
  const decrypted2 = Crypto.decrypt(
    ciphertext2,
    chachaKey,
    null,
    "chacha20-poly1305"
  );

  assert(
    plaintext.equals(decrypted2),
    "ChaCha20 decryption should match original plaintext"
  );
  console.log("✓ ChaCha20-Poly1305 encryption/decryption works");

  // Test encapsulation/decapsulation
  const encapsulationKey = Crypto.generateEncapsulationKey();
  const encapsulation = Crypto.encapsulate(encapsulationKey.publicKeyBytes);
  const decapsulatedSecret = Crypto.decapsulate(
    encapsulation.ciphertext,
    encapsulationKey.privateKeyBytes
  );

  assert(
    encapsulation.sharedSecret.equals(decapsulatedSecret),
    "Decapsulated secret should match original"
  );
  console.log("✓ ML-KEM encapsulation/decapsulation works");

  // Test signing/verification
  const signingKey = Crypto.generateSignatureKey();
  const message = Buffer.from("Sign this message", "utf8");
  const signature = Crypto.sign(message, signingKey.privateKeyBytes);
  const isValid = Crypto.verify(message, signature, signingKey.publicKeyBytes);

  assert(isValid === true, "Signature should be valid");
  console.log("✓ ML-DSA signing/verification works");

  // Test hashing
  const mess = "SilverTiger";
  const data = Buffer.from(mess, "utf8");
  const hash = Crypto.hash(data);
  const expectedHash = Buffer.from(
    "fe2f0faa017659760fea72c8ac6f1bdc6433d31ebe2e533f5e5fe6aedf74fc57",
    "hex"
  );
  assert(hash.length === 32, "SHA-256 hash should be 32 bytes");
  assert(hash.equals(expectedHash), "SHA-256 hash should match expected value");
  console.log("✓ SHA-256 hashing works");

  // Test HMAC
  const hmacMess = "SilverTiger";
  const hmacKey = Buffer.from("secret_key", "utf8");
  const hmacBuf = Buffer.from(hmacMess, "utf8");
  const hmacDigest = Crypto.hmac(hmacKey, hmacBuf);
  const expectedHmac = Buffer.from(
    "4e792a8c6302ec5f768b451d3e3639ae3f3b3f9e6e37ef7db44dabdd46470148",
    "hex"
  );
  assert(hmacDigest.equals(expectedHmac), "HMAC should match expected value");
  console.log("✓ HMAC works");

  // Test password derivation
  const password = Buffer.from("my_password", "utf8");
  const salt = Buffer.from("random_salt", "utf8");
  const derivedKey = Crypto.derivePassword(password, salt);

  const expectedDerivedKey = Buffer.from(
    "036af3e5e0ad10ada4f0b6cdfb10d884b19b7fa1f7953c417f8b72aa1796b522",
    "hex"
  );
  assert(derivedKey.length === 32, "Derived key should be 32 bytes");
  assert(
    derivedKey.equals(expectedDerivedKey),
    "Derived key should match expected value"
  );
  console.log("✓ Password derivation works");

  console.log("✓ Crypto tests passed");
}

testCrypto();
