<?php

declare(strict_types=1);

/**
 * Example: RSA-OAEP asymmetric encryption and decryption.
 *
 * OAEP (Optimal Asymmetric Encryption Padding) is the recommended padding
 * scheme.  PKCS1 v1.5 encryption is vulnerable to Bleichenbacher's oracle
 * attack and must not be used for new designs.
 *
 * Security notes:
 *  - RSA encryption is only suitable for small payloads (key wrapping).
 *    For bulk data, use AES and encrypt the AES key with RSA (hybrid encryption).
 *  - OAEP uses SHA-1 by default per the RFC; you can upgrade to SHA-256 via
 *    withHash('sha256')->withMGFHash('sha256').
 *  - The plaintext size limit for OAEP with SHA-1 and a 2048-bit key is
 *    214 bytes.  Attempting to encrypt more will throw a LengthException.
 *
 * @security OAEP decryption uses bitwise OR instead of logical OR in the
 *           final check to prevent Manger's chosen-ciphertext attack via
 *           short-circuit evaluation timing differences.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use phpseclib4\Crypt\RSA;

$private_key = RSA::createKey(2048);
$public_key  = $private_key->getPublicKey();

// Switch both keys to OAEP+SHA-256 for stronger padding.
$private_key = $private_key->withHash('sha256')->withMGFHash('sha256');
$public_key  = $public_key->withHash('sha256')->withMGFHash('sha256');

$plaintext  = 'Symmetric key material (32 bytes)';

// Encrypt with the public key.
$ciphertext = $public_key->encrypt($plaintext);
echo 'Ciphertext length: ' . strlen($ciphertext) . ' bytes' . PHP_EOL;

// Decrypt with the private key.
$decrypted  = $private_key->decrypt($ciphertext);
echo 'Decrypted: ' . $decrypted . PHP_EOL;

assert($decrypted === $plaintext, 'OAEP round-trip failed!');
echo 'OAEP round-trip OK.' . PHP_EOL;
