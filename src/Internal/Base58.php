<?php

declare(strict_types=1);

/*
 * This file is part of the PHP Bitcoin BOLT11 package.
 *
 * (c) Jorijn Schrijvershof <jorijn@jorijn.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Jorijn\Bitcoin\Bolt11\Internal;

/**
 * Base58Check encoding for P2PKH and P2SH fallback addresses.
 *
 * Only encoding is needed: BOLT #11 carries the raw hash, and this library
 * turns it into the address a wallet would show.
 *
 * @internal not covered by the backward compatibility promise
 */
final class Base58
{
    private const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    /**
     * @param int    $version one byte: 0x00 for P2PKH on mainnet, 0x05 for P2SH, ...
     * @param string $payload raw bytes, usually a 20-byte hash
     */
    public static function encodeCheck(int $version, string $payload): string
    {
        $data = \chr($version).$payload;

        // The checksum is the first four bytes of a double SHA-256.
        return self::encode($data.substr(hash('sha256', hash('sha256', $data, true), true), 0, 4));
    }

    public static function encode(string $bytes): string
    {
        if ('' === $bytes) {
            return '';
        }

        $number = gmp_import($bytes);
        $encoded = '';
        while (gmp_cmp($number, 0) > 0) {
            $encoded = self::ALPHABET[gmp_intval(gmp_mod($number, 58))].$encoded;
            $number = gmp_div_q($number, 58);
        }

        // Each leading zero byte is a leading "1": the number itself loses them.
        $leadingZeros = \strlen($bytes) - \strlen(ltrim($bytes, "\0"));

        return str_repeat(self::ALPHABET[0], $leadingZeros).$encoded;
    }
}
