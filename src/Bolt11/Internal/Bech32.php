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
 * Bech32 (BIP 173) and bech32m (BIP 350).
 *
 * BOLT #11 invoices use bech32 without the 90-character limit of BIP 173,
 * because an invoice with routing hints is easily longer. Segwit fallback
 * addresses use bech32 for witness version 0 and bech32m for version 1 and up.
 *
 * @internal not covered by the backward compatibility promise
 */
final class Bech32
{
    public const CHECKSUM_BECH32 = 1;
    public const CHECKSUM_BECH32M = 0x2BC830A3;

    private const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    private const GENERATOR = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3];

    /**
     * Splits a bech32 string into its human-readable part and data words, and
     * verifies the checksum.
     *
     * @param ?int $maxLength null for no limit (BOLT #11), 90 for addresses
     *
     * @return array{string, list<int>} the lowercase human-readable part and the data words without the checksum
     *
     * @throws \InvalidArgumentException when the string is not valid bech32 with this checksum
     */
    public static function decode(string $string, int $checksum = self::CHECKSUM_BECH32, ?int $maxLength = null): array
    {
        if (null !== $maxLength && \strlen($string) > $maxLength) {
            throw new \InvalidArgumentException('bech32 string is too long');
        }

        // BIP 173: only printable US-ASCII, and either all lowercase or all
        // uppercase. A mix would let two different strings decode to the same data.
        if (1 !== preg_match('/^[\x21-\x7e]+$/', $string)) {
            throw new \InvalidArgumentException('bech32 string contains invalid characters');
        }

        $lower = strtolower($string);
        if ($string !== $lower && $string !== strtoupper($string)) {
            throw new \InvalidArgumentException('bech32 string uses mixed case');
        }

        // The separator is the last "1": the human-readable part may contain
        // a "1" itself, the data part never does (it is not in the charset).
        $separator = strrpos($lower, '1');
        if (false === $separator || 0 === $separator) {
            throw new \InvalidArgumentException('bech32 string has no separator or no human-readable part');
        }

        if (\strlen($lower) - $separator - 1 < 6) {
            throw new \InvalidArgumentException('bech32 string is too short for a checksum');
        }

        $hrp = substr($lower, 0, $separator);
        $words = [];
        foreach (str_split(substr($lower, $separator + 1)) as $character) {
            $word = strpos(self::CHARSET, $character);
            if (false === $word) {
                throw new \InvalidArgumentException(\sprintf('bech32 string contains an invalid character "%s"', $character));
            }

            $words[] = $word;
        }

        if (self::polymod(array_merge(self::expandHrp($hrp), $words)) !== $checksum) {
            throw new \InvalidArgumentException('bech32 checksum is invalid');
        }

        return [$hrp, \array_slice($words, 0, -6)];
    }

    /**
     * @param list<int> $words 5-bit values
     */
    public static function encode(string $hrp, array $words, int $checksum = self::CHECKSUM_BECH32): string
    {
        $values = array_merge(self::expandHrp($hrp), $words, [0, 0, 0, 0, 0, 0]);
        $polymod = self::polymod($values) ^ $checksum;

        $string = $hrp.'1';
        foreach ($words as $word) {
            $string .= self::CHARSET[$word];
        }

        for ($i = 0; $i < 6; ++$i) {
            $string .= self::CHARSET[($polymod >> (5 * (5 - $i))) & 31];
        }

        return $string;
    }

    /**
     * Encodes a segwit address (BIP 173 for version 0, BIP 350 for 1 to 16).
     *
     * @throws \InvalidArgumentException when the version or program length is not valid
     */
    public static function encodeSegwitAddress(string $hrp, int $version, string $program): string
    {
        $length = \strlen($program);
        if ($version < 0 || $version > 16) {
            throw new \InvalidArgumentException('witness version must be between 0 and 16');
        }

        // BIP 141: a program is 2 to 40 bytes, and version 0 only defines 20
        // (P2WPKH) and 32 (P2WSH). Other lengths cannot be spent to.
        if ($length < 2 || $length > 40 || (0 === $version && 20 !== $length && 32 !== $length)) {
            throw new \InvalidArgumentException(\sprintf('witness program of %d bytes is not valid for version %d', $length, $version));
        }

        return self::encode(
            $hrp,
            array_merge([$version], self::bytesToWords($program)),
            0 === $version ? self::CHECKSUM_BECH32 : self::CHECKSUM_BECH32M,
        );
    }

    /**
     * Regroups a list of $from-bit values into $to-bit values.
     *
     * With $pad, the last group is padded with zero bits (used when encoding);
     * without, leftover bits are dropped. BOLT #11 drops them as well when it
     * reads a field as bytes: a 52-word field is 260 bits, so 32 bytes and 4
     * bits of padding.
     *
     * @param list<int> $values
     *
     * @return list<int>
     */
    public static function convertBits(array $values, int $from, int $to, bool $pad): array
    {
        $accumulator = 0;
        $bits = 0;
        $maxValue = (1 << $to) - 1;
        $result = [];

        foreach ($values as $value) {
            // Only keep the bits that can still contribute: this stops the
            // accumulator from growing for long inputs.
            $accumulator = (($accumulator << $from) | $value) & ((1 << ($from + $to - 1)) - 1);
            $bits += $from;

            while ($bits >= $to) {
                $bits -= $to;
                $result[] = ($accumulator >> $bits) & $maxValue;
            }
        }

        if ($pad && $bits > 0) {
            $result[] = ($accumulator << ($to - $bits)) & $maxValue;
        }

        return $result;
    }

    /**
     * Splits bytes into 5-bit words, padding the last one with zero bits.
     *
     * @return list<int>
     */
    public static function bytesToWords(string $bytes): array
    {
        return self::convertBits(array_map(\ord(...), str_split($bytes)), 8, 5, true);
    }

    /**
     * Reads 5-bit words as bytes; trailing bits that do not fill a byte are dropped.
     *
     * @param list<int> $words
     */
    public static function wordsToBytes(array $words, bool $pad = false): string
    {
        $bytes = self::convertBits($words, 5, 8, $pad);

        return [] === $bytes ? '' : pack('C*', ...$bytes);
    }

    /**
     * @param list<int> $values
     */
    private static function polymod(array $values): int
    {
        $checksum = 1;
        foreach ($values as $value) {
            $top = $checksum >> 25;
            $checksum = (($checksum & 0x1FFFFFF) << 5) ^ $value;
            for ($i = 0; $i < 5; ++$i) {
                if ((($top >> $i) & 1) === 1) {
                    $checksum ^= self::GENERATOR[$i];
                }
            }
        }

        return $checksum;
    }

    /**
     * @return list<int>
     */
    private static function expandHrp(string $hrp): array
    {
        $high = [];
        $low = [];
        foreach (str_split($hrp) as $character) {
            $high[] = \ord($character) >> 5;
            $low[] = \ord($character) & 31;
        }

        return array_merge($high, [0], $low);
    }
}
