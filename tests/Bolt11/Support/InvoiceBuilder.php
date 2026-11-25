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

namespace Tests\Jorijn\Bitcoin\Bolt11\Support;

use Jorijn\Bitcoin\Bolt11\Internal\Bech32;
use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;

/**
 * Builds signed invoices for tests, so every rule of the decoder can be tested
 * with an invoice that is valid except for the one thing under test.
 *
 * Signs with the private key of the BOLT #11 examples. The nonce is derived
 * from the key and the hash (not RFC 6979, but just as deterministic), which
 * is fine for tests and nothing else.
 */
final class InvoiceBuilder
{
    /** The key every example in BOLT #11 is signed with. */
    public const PRIVATE_KEY = 'e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734';
    public const PUBLIC_KEY = '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad';

    public const PAYMENT_HASH = '0001020304050607080900010203040506070809000102030405060708090102';
    public const PAYMENT_SECRET = '1111111111111111111111111111111111111111111111111111111111111111';
    public const TIMESTAMP = 1496314658;

    /** @var list<int> */
    private array $fieldWords = [];

    private bool $highS = false;

    private function __construct(
        private readonly string $humanReadablePart,
        private readonly int $timestamp,
    ) {}

    public static function create(string $humanReadablePart = 'lnbc', int $timestamp = self::TIMESTAMP): self
    {
        return new self($humanReadablePart, $timestamp);
    }

    /**
     * A minimal invoice that passes strict mode: `p`, `s` and `d`.
     */
    public static function valid(string $humanReadablePart = 'lnbc'): self
    {
        return self::create($humanReadablePart)
            ->withBytesField(1, (string) hex2bin(self::PAYMENT_HASH))
            ->withBytesField(16, (string) hex2bin(self::PAYMENT_SECRET))
            ->withBytesField(13, 'test')
        ;
    }

    /**
     * @param list<int> $words
     */
    public function withField(int $type, array $words): self
    {
        $clone = clone $this;
        $clone->fieldWords = array_merge($clone->fieldWords, [$type, \count($words) >> 5, \count($words) & 31], $words);

        return $clone;
    }

    public function withBytesField(int $type, string $bytes): self
    {
        return $this->withField($type, self::bytesToWords($bytes));
    }

    public function withIntField(int $type, int $value, int $leadingZeros = 0): self
    {
        return $this->withField($type, array_merge(array_fill(0, $leadingZeros, 0), self::intToWords($value)));
    }

    /**
     * Words appended after the fields as they are, for malformed field data.
     *
     * @param list<int> $words
     */
    public function withRawWords(array $words): self
    {
        $clone = clone $this;
        $clone->fieldWords = array_merge($clone->fieldWords, $words);

        return $clone;
    }

    /**
     * Sign with s above n/2. Both s and n − s verify, see the low-S rule.
     */
    public function withHighS(): self
    {
        $clone = clone $this;
        $clone->highS = true;

        return $clone;
    }

    public function build(): string
    {
        $dataWords = $this->dataWords();
        $hash = hash('sha256', $this->humanReadablePart.Bech32::wordsToBytes($dataWords, true), true);
        [$signature, $recoveryId] = $this->sign($hash);

        return $this->encode($dataWords, $signature, $recoveryId);
    }

    /**
     * The invoice with a signature of your choosing, which need not be valid.
     */
    public function buildWithSignature(string $signature, int $recoveryId): string
    {
        return $this->encode($this->dataWords(), $signature, $recoveryId);
    }

    /**
     * @return list<int>
     */
    public static function intToWords(int $value): array
    {
        $words = [];
        while ($value > 0) {
            array_unshift($words, $value & 31);
            $value >>= 5;
        }

        return $words;
    }

    /**
     * @return list<int>
     */
    public static function bytesToWords(string $bytes): array
    {
        return Bech32::bytesToWords($bytes);
    }

    /**
     * @return list<int>
     */
    private function dataWords(): array
    {
        return array_merge(array_pad(self::intToWords($this->timestamp), -7, 0), $this->fieldWords);
    }

    /**
     * @param list<int> $dataWords
     */
    private function encode(array $dataWords, string $signature, int $recoveryId): string
    {
        return Bech32::encode($this->humanReadablePart, array_merge($dataWords, self::bytesToWords($signature.\chr($recoveryId))));
    }

    /**
     * Textbook ECDSA: s = k⁻¹ · (e + r · d) mod n.
     *
     * @return array{string, int} r || s and the recovery id
     */
    private function sign(string $hash): array
    {
        $order = Secp256k1::order();
        $privateKey = gmp_init(self::PRIVATE_KEY, 16);
        $nonce = gmp_mod(gmp_import(hash('sha256', hex2bin(self::PRIVATE_KEY).$hash, true)), $order);

        // R = k·G; its x is r, the parity of its y goes in the recovery id.
        $point = Secp256k1::multiplyGenerator($nonce);
        $x = gmp_import(substr($point, 1));
        $r = gmp_mod($x, $order);
        $recoveryId = ("\x03" === $point[0] ? 1 : 0) | (gmp_cmp($x, $order) >= 0 ? 2 : 0);

        $nonceInverse = gmp_invert($nonce, $order);
        if (false === $nonceInverse) {
            throw new \LogicException('the nonce is zero, pick another message');
        }

        $s = gmp_mod($nonceInverse * (gmp_import($hash) + $r * $privateKey), $order);

        // Negating s negates R as well, which flips the parity of its y.
        $isHigh = gmp_cmp($s, gmp_div_q($order, 2)) > 0;
        if ($isHigh !== $this->highS) {
            $s = $order - $s;
            $recoveryId ^= 1;
        }

        return [self::pad32($r).self::pad32($s), $recoveryId];
    }

    private static function pad32(\GMP $value): string
    {
        return str_pad(gmp_export($value), 32, "\0", STR_PAD_LEFT);
    }
}
