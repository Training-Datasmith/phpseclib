# phpseclib Architecture

## Purpose

phpseclib is a pure-PHP cryptography library providing RSA, DSA, EC, DH, AES, and other algorithms without requiring native OpenSSL extensions (though it uses them when available for performance). It targets PHP 7.4+ and aims for RFC-compliant implementations with extensive key-format support.

## Directory Structure

```
phpseclib/
  Crypt/
    AES.php                 — AES block cipher (wraps Rijndael, fixed 128-bit block)
    Common/
      SymmetricKey.php      — Base for all symmetric ciphers (mode handling, padding, buffering)
      BlockCipher.php       — Marker base for block ciphers
      StreamCipher.php      — Base for stream ciphers
      AsymmetricKey.php     — Base for all asymmetric key types
      PublicKey.php         — Public-key interface
      PrivateKey.php        — Private-key interface
      Traits/
        Fingerprint.php     — SSH/PGP fingerprint computation
        PasswordProtected.php — Key encryption at rest
    RSA/
      PublicKey.php         — RSAES-OAEP, RSAES-PKCS1-v1.5, RSASSA-PSS, RSASSA-PKCS1-v1.5
      PrivateKey.php        — Decryption and signing; CRT optimisation; RSA blinding
      Formats/Keys/         — PKCS#1, PKCS#8, OpenSSH, PuTTY, PSS, JWK, MSBLOB, XML, Raw
    EC/
      PrivateKey.php / PublicKey.php — ECDSA, ECDH
      Curves/               — ~80 named curves (NIST, Brainpool, secp*, Curve25519, Curve448)
    DSA/PrivateKey.php / PublicKey.php
    DH/PrivateKey.php / PublicKey.php / Parameters.php
  Exception/                — 30+ domain-specific exception classes
  File/ASN1/                — BER/DER encoder-decoder
  Math/BigInteger.php       — Arbitrary-precision arithmetic (GMP, BCMath, or pure-PHP)
  Net/SSH2.php / SFTP.php   — SSH-2 and SFTP clients
```

## Key Design Decisions

- **Backend selection**: BigInteger, symmetric ciphers, and key loading all auto-select between native extensions (GMP, OpenSSL) and pure-PHP fallbacks.
- **RSA blinding**: `PrivateKey::exponentiate()` applies random blinding factors when `$enableBlinding` is true (default), protecting against timing and fault attacks.
- **Constant-time comparisons**: Signature verification uses `hash_equals()` throughout to prevent timing side channels.
- **Immutable key configuration**: `withHash()`, `withPadding()`, `withLabel()` return new instances, preventing accidental shared-state bugs.
- **Plugin architecture**: Key formats and signature formats are discovered via `validatePlugin()`, allowing third-party format handlers without touching core code.
- **PKCS#1 v2.0+ default**: New code defaults to RSASSA-PSS and RSAES-OAEP; PKCS#1 v1.5 padding is available but not the default.

## Security Boundaries

- Raw (no-padding) RSA operations are exposed but documented as insecure; they exist for interoperability with legacy protocols only.
- PKCS#1 v1.5 decryption (`rsaes_pkcs1_v1_5_decrypt`) does not implement Bleichenbacher countermeasures — callers should use OAEP instead.
- Key files loaded from disk do not require specific filesystem permissions; callers are responsible for restricting access.

## Extension Points

- Add new key formats by implementing `savePublicKey` / `loadPublicKey` and registering via the plugin system.
- Add new elliptic curves by extending `BaseCurves\Prime` or `BaseCurves\Binary` and placing them under `Crypt/EC/Curves/`.

## Dependency Flow

```
RSA\PrivateKey / PublicKey
    └─ Common\AsymmetricKey  (plugin loading, format validation)
         └─ Math\BigInteger  (modular exponentiation)
              └─ GMP | BCMath | pure-PHP
    └─ File\ASN1             (BER/DER encoding for PKCS formats)
    └─ Crypt\Hash            (OAEP / PSS hash operations)
    └─ Crypt\Random          (CSPRNG wrapper)
```
