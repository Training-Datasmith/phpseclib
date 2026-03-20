<?php

declare(strict_types=1);

/**
 * Example: AES-256-CTR symmetric encryption.
 *
 * CTR mode turns a block cipher into a stream cipher.  Unlike CBC it does not
 * require padding and is parallelisable.  phpseclib uses OpenSSL when available
 * and falls back to a pure-PHP implementation otherwise.
 *
 * Security notes:
 *  - You MUST use a unique (key, IV) pair for every message.  Reusing an IV
 *    with CTR mode is catastrophic — it allows XOR-recovery of both plaintexts.
 *  - AES-CTR provides confidentiality only; it does not authenticate the
 *    ciphertext.  Add an HMAC (or use GCM mode) for integrity protection.
 *  - For authenticated encryption, prefer AES-GCM via PHP's openssl_encrypt()
 *    or the php-encryption library (which uses AES-256-CTR + HMAC-SHA256).
 *  - Use a cryptographically random key and IV (random_bytes()).
 *
 * @security CTR mode with a static key but repeating IV leaks plaintext XOR.
 *           Always generate a fresh random IV per message.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use phpseclib4\Crypt\AES;

$aes = new AES('ctr');

// 256-bit random key and 128-bit random IV.
$key = random_bytes(32);
$iv  = random_bytes(16);

$aes->setKey($key);
$aes->setIV($iv);

$plaintext  = 'This is a secret message encrypted with AES-256-CTR.';
$ciphertext = $aes->encrypt($plaintext);
echo 'Ciphertext (hex): ' . bin2hex($ciphertext) . PHP_EOL;

// Reset IV before decrypting (CTR is stateful in phpseclib).
$aes->setIV($iv);
$decrypted = $aes->decrypt($ciphertext);
echo 'Decrypted: ' . $decrypted . PHP_EOL;

assert($decrypted === $plaintext, 'AES-CTR round-trip failed!');
echo 'AES-CTR round-trip OK.' . PHP_EOL;
