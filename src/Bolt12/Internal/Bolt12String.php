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

namespace Jorijn\Bitcoin\Bolt12\Internal;

use Jorijn\Bitcoin\Bolt11\Internal\Bech32;

/**
 * The text form of BOLT #12 messages: a human-readable prefix, "1", and the
 * TLV stream in bech32 characters, without the bech32 checksum.
 *
 * @internal not covered by the backward compatibility promise
 *
 * @see https://github.com/lightning/bolts/blob/master/12-offer-encoding.md#encoding
 */
final class Bolt12String
{
    private const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

    /**
     * @return array{string, string} the lowercase human-readable prefix and the TLV stream bytes
     *
     * @throws \InvalidArgumentException when the string is not a well-formed BOLT #12 string
     */
    public static function decode(string $string): array
    {
        // A "+" followed by optional whitespace joins two pieces of a long
        // string, but only between two bech32 characters: a "+" at either end,
        // or two in a row, is an error (spec format-string vectors).
        $characters = preg_quote(self::CHARSET.strtoupper(self::CHARSET), '/');
        $joined = preg_replace('/(?<=['.$characters.'])\+\s*(?=['.$characters.'])/', '', $string);
        if (null === $joined || str_contains($joined, '+')) {
            throw new \InvalidArgumentException('"+" may only join two bech32 characters');
        }

        if (1 !== preg_match('/^[\x21-\x7e]+$/', $joined)) {
            throw new \InvalidArgumentException('string contains invalid characters');
        }

        // Either all lowercase or all uppercase (QR codes use uppercase).
        $lower = strtolower($joined);
        if ($joined !== $lower && $joined !== strtoupper($joined)) {
            throw new \InvalidArgumentException('string uses mixed case');
        }

        $separator = strrpos($lower, '1');
        if (false === $separator || 0 === $separator) {
            throw new \InvalidArgumentException('string has no "1" separator or no prefix');
        }

        $words = [];
        foreach (str_split(substr($lower, $separator + 1)) as $character) {
            $word = strpos(self::CHARSET, $character);
            if (false === $word) {
                throw new \InvalidArgumentException(\sprintf('string contains an invalid character "%s"', $character));
            }

            $words[] = $word;
        }

        // 5-bit words regrouped as bytes leave at most 4 bits over, and those
        // must be zero. Anything else means two different strings for the same
        // bytes, which BIP 173 rules out (spec vector "padding exceeds 4-bit limit").
        $leftoverBits = (\count($words) * 5) % 8;
        if ([] !== $words && ($leftoverBits >= 5 || 0 !== ($words[\count($words) - 1] & ((1 << $leftoverBits) - 1)))) {
            throw new \InvalidArgumentException('string has invalid padding');
        }

        return [substr($lower, 0, $separator), Bech32::wordsToBytes($words)];
    }

    /**
     * Encodes TLV bytes with a prefix, in lowercase and without "+" joins.
     */
    public static function encode(string $prefix, string $bytes): string
    {
        $string = $prefix.'1';
        foreach (Bech32::bytesToWords($bytes) as $word) {
            $string .= self::CHARSET[$word];
        }

        return $string;
    }
}
