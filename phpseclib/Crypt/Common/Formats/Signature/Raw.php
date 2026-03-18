<?php

/**
 * Raw Signature Handler
 *
 * PHP version 5
 *
 * Handles signatures as arrays
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\Common\Formats\Signature;

use phpseclib4\Math\BigInteger;

/**
 * Raw Signature Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Raw
{
    /**
     * Loads a signature
     *
     * @return array|bool
     */
    public static function load(array $sig)
    {
        return match (true) {
            !is_array($sig), !isset($sig['r']) || !isset($sig['s']), !$sig['r'] instanceof BigInteger, !$sig['s'] instanceof BigInteger => false,
            default => [
                'r' => $sig['r'],
                's' => $sig['s'],
            ],
        };
    }

    /**
     * Returns a signature in the appropriate format
     */
    public static function save(BigInteger $r, BigInteger $s): string
    {
        return compact('r', 's');
    }
}
