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

use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use Jorijn\Bitcoin\Bolt12\Exception\InvalidFieldException;
use Jorijn\Bitcoin\Bolt12\Exception\MalformedTlvException;
use Jorijn\Bitcoin\Bolt12\Exception\UnknownRequiredFeatureException;
use Jorijn\Bitcoin\Bolt12\Model\Features;

/**
 * Reads the value types BOLT #12 fields share (text, truncated integers,
 * keys, hashes, features), so offers, invoices and payer proofs read them
 * the same way.
 *
 * @internal not covered by the backward compatibility promise
 */
final class FieldReader
{
    /** 9999-12-31T23:59:59Z: a later moment does not fit a four-digit year, and is no real expiry. */
    public const MAX_TIMESTAMP = 253_402_300_799;

    /**
     * BOLT #1 strings: valid UTF-8 without control, format, surrogate or
     * private-use characters, or line and paragraph separators. These could
     * hide text from the user or change how the rest of it reads.
     */
    public static function text(?TlvRecord $record, string $name): ?string
    {
        if (null === $record) {
            return null;
        }

        // preg_match() returns false, not 1, on invalid UTF-8 with the u flag.
        if (0 !== preg_match('/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\x{2028}\x{2029}]/u', $record->value)) {
            throw new InvalidFieldException(\sprintf('%s is not valid UTF-8 text', $name));
        }

        return $record->value;
    }

    /**
     * A truncated integer (tu64 and friends): big-endian without leading
     * zero bytes, so each number has exactly one encoding.
     */
    public static function truncated(TlvRecord $record, int $maxBytes, string $name): int
    {
        try {
            return (new ByteReader($record->value))->readTruncated($maxBytes);
        } catch (\InvalidArgumentException $exception) {
            throw new MalformedTlvException(\sprintf('%s: %s', $name, $exception->getMessage()), 0, $exception);
        }
    }

    public static function timestamp(TlvRecord $record, string $name): int
    {
        $timestamp = self::truncated($record, 8, $name);
        if ($timestamp > self::MAX_TIMESTAMP) {
            throw new InvalidFieldException(\sprintf('%s is out of range', $name));
        }

        return $timestamp;
    }

    /**
     * @return string hex
     */
    public static function fixed(TlvRecord $record, int $length, string $name): string
    {
        if (\strlen($record->value) !== $length) {
            throw new MalformedTlvException(\sprintf('%s must be %d bytes', $name, $length));
        }

        return bin2hex($record->value);
    }

    /**
     * @return string hex, a 33-byte compressed public key
     */
    public static function point(TlvRecord $record, string $name): string
    {
        $key = self::fixed($record, 33, $name);
        if (!Secp256k1::isValidPublicKey($record->value)) {
            throw new InvalidFieldException(\sprintf('%s is not a valid public key', $name));
        }

        return $key;
    }

    /**
     * @return string hex, 64 bytes
     */
    public static function signature(TlvRecord $record, string $name = 'signature'): string
    {
        return self::fixed($record, 64, $name);
    }

    /**
     * @param null|list<int> $known even bits the reader understands; null
     *                              accepts every bit, for a reader that only
     *                              reports features instead of acting on them
     */
    public static function features(?TlvRecord $record, string $name, ?array $known = []): Features
    {
        if (null === $record) {
            return new Features();
        }

        // Minimal encoding: no leading zero bytes, so each set of features
        // has exactly one encoding.
        if ('' !== $record->value && "\0" === $record->value[0]) {
            throw new InvalidFieldException(\sprintf('%s is not minimally encoded', $name));
        }

        $features = Features::fromBytes($record->value);
        if (null === $known) {
            return $features;
        }

        $unknown = $features->getUnknownRequiredBits($known);
        if ([] !== $unknown) {
            throw new UnknownRequiredFeatureException(\sprintf('%s requires unknown feature bits %s', $name, implode(', ', $unknown)), $unknown);
        }

        return $features;
    }
}
