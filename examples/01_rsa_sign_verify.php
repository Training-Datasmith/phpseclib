<?php

declare(strict_types=1);

/**
 * Example: RSA key generation, signing, and signature verification.
 *
 * Defaults to RSASSA-PSS (probabilistic, recommended).  PKCS#1 v1.5 is
 * available but should be avoided in new designs.
 *
 * Security notes:
 *  - Use at least 2048-bit keys; 3072 or 4096 bits for long-lived keys.
 *  - PSS padding is strongly preferred over PKCS1 v1.5 for new code.
 *  - Never use ENCRYPTION_NONE (raw RSA) — it is deterministic and malleable.
 *  - Store private keys protected by a password (withPassword()) at rest.
 *  - RSA blinding is enabled by default in phpseclib to resist timing attacks.
 *
 * @security RSA private-key operations are protected against timing side
 *           channels via random blinding factors (see PrivateKey::blind()).
 */

require_once __DIR__ . '/../vendor/autoload.php';

use phpseclib4\Crypt\RSA;

// Generate a 3072-bit key pair (PSS signing, OAEP encryption by default).
$private_key = RSA::createKey(3072);
$public_key  = $private_key->getPublicKey();

echo 'Key size: ' . $private_key->getLength() . ' bits' . PHP_EOL;

// Sign a message.
$message   = 'The quick brown fox jumps over the lazy dog';
$signature = $private_key->sign($message);
echo 'Signature (base64): ' . base64_encode($signature) . PHP_EOL;

// Verify the signature.
$valid = $public_key->verify($message, $signature);
echo 'Signature valid: ' . ($valid ? 'YES' : 'NO') . PHP_EOL;

// Demonstrate that a tampered message is rejected.
$tampered = 'The quick brown fox jumps over the lazy cat';
$invalid  = $public_key->verify($tampered, $signature);
echo 'Tampered message valid: ' . ($invalid ? 'YES (BAD!)' : 'NO (correct)') . PHP_EOL;

assert($valid  === true,  'Valid signature rejected');
assert($invalid === false, 'Invalid signature accepted');
echo 'Signature round-trip OK.' . PHP_EOL;
