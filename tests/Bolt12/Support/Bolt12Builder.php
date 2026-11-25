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

namespace Tests\Jorijn\Bitcoin\Bolt12\Support;

use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use Jorijn\Bitcoin\Bolt12\Internal\Bolt12String;
use Jorijn\Bitcoin\Bolt12\Internal\MerkleTree;
use Jorijn\Bitcoin\Bolt12\Internal\TlvRecord;

/**
 * Builds BOLT #12 strings for tests, so every rule of the decoder can be
 * tested with a message that is valid except for the one thing under test.
 *
 * Signing follows BIP-340 exactly (Secp256k1Test reproduces the official
 * signing vectors with it). It is not constant-time: for tests only.
 */
final class Bolt12Builder
{
    /** The issuer key of the BOLT #12 payer proof vectors (0x46 repeated). */
    public const ISSUER_SECRET = '4646464646464646464646464646464646464646464646464646464646464646';
    public const ISSUER_ID = '024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382';

    /** The payer key of the same vectors (0x42 repeated). */
    public const PAYER_SECRET = '4242424242424242424242424242424242424242424242424242424242424242';
    public const PAYER_ID = '0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c';

    public const PAYMENT_HASH = '0101010101010101010101010101010101010101010101010101010101010101';
    public const CREATED_AT = 1_700_000_000;

    /** @var array<int, string> raw values by type */
    private array $records = [];

    /** @var list<string> records appended as raw bytes, for malformed streams */
    private array $rawRecords = [];

    public static function create(): self
    {
        return new self();
    }

    /**
     * An offer with a description and an issuer id: the least a valid offer needs.
     */
    public static function offer(): self
    {
        return self::create()
            ->with(10, 'Test vectors')
            ->with(22, (string) hex2bin(self::ISSUER_ID))
        ;
    }

    /**
     * An unsigned invoice request for offer(), for 1000 msat.
     */
    public static function invoiceRequest(): self
    {
        return self::offer()
            ->with(0, str_repeat("\x07", 16))
            ->withInt(82, 1000)
            ->with(88, (string) hex2bin(self::PAYER_ID))
        ;
    }

    /**
     * An unsigned invoice for invoiceRequest(), with one blinded path.
     */
    public static function invoice(): self
    {
        return self::invoiceRequest()
            ->with(160, self::blindedPath())
            ->with(162, self::payInfo())
            ->withInt(164, self::CREATED_AT)
            ->with(168, (string) hex2bin(self::PAYMENT_HASH))
            ->withInt(170, 1000)
            ->with(176, (string) hex2bin(self::ISSUER_ID))
        ;
    }

    public function with(int $type, string $value): self
    {
        $clone = clone $this;
        $clone->records[$type] = $value;

        return $clone;
    }

    /**
     * Sets a truncated integer (tu64 and friends): no leading zero bytes.
     */
    public function withInt(int $type, int $value): self
    {
        return $this->with($type, self::truncated($value));
    }

    public function without(int $type): self
    {
        $clone = clone $this;
        unset($clone->records[$type]);

        return $clone;
    }

    /**
     * Appends bytes after the sorted records, as they are: for streams the
     * builder would otherwise never produce.
     */
    public function withRawRecord(string $bytes): self
    {
        $clone = clone $this;
        $clone->rawRecords[] = $bytes;

        return $clone;
    }

    /**
     * Adds the signature record (type 240) over the current records.
     *
     * @param string $messageName "invoice_request" or "invoice"
     */
    public function sign(string $messageName, string $secretKey): self
    {
        $unsigned = $this->without(240);
        $hash = MerkleTree::signatureHash($messageName, 'signature', MerkleTree::root(TlvRecord::parseStream($unsigned->bytes())));

        return $unsigned->with(240, self::schnorrSign($hash, $secretKey, str_repeat("\0", 32)));
    }

    public function bytes(): string
    {
        $records = $this->records;
        ksort($records);

        $bytes = '';
        foreach ($records as $type => $value) {
            $bytes .= self::bigSize($type).self::bigSize(\strlen($value)).$value;
        }

        return $bytes.implode('', $this->rawRecords);
    }

    public function encode(string $prefix): string
    {
        return Bolt12String::encode($prefix, $this->bytes());
    }

    public static function bigSize(int $value): string
    {
        return match (true) {
            $value < 0xFD => \chr($value),
            $value <= 0xFFFF => "\xFD".pack('n', $value),
            $value <= 0xFFFFFFFF => "\xFE".pack('N', $value),
            default => "\xFF".pack('J', $value),
        };
    }

    public static function truncated(int $value): string
    {
        return ltrim(pack('J', $value), "\0");
    }

    /**
     * A blinded path with a public key as introduction node and one hop.
     */
    public static function blindedPath(?string $introductionNode = null, int $hops = 1): string
    {
        $path = (string) hex2bin($introductionNode ?? '027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007')
            .(string) hex2bin('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991')
            .\chr($hops);
        for ($i = 0; $i < $hops; ++$i) {
            $path .= (string) hex2bin('02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145').pack('n', 3).'abc';
        }

        return $path;
    }

    /**
     * A blinded_payinfo entry.
     */
    public static function payInfo(string $features = '', int $htlcMaximumMsat = 2_000_000_000): string
    {
        return pack('NNnJJn', 1000, 100, 144, 1, $htlcMaximumMsat, \strlen($features)).$features;
    }

    public static function publicKey(string $secretKey): string
    {
        return bin2hex(Secp256k1::multiplyGenerator(gmp_init($secretKey, 16)));
    }

    /**
     * BIP-340 signing, step by step as the BIP's default signing algorithm.
     *
     * @see https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing
     */
    public static function schnorrSign(string $message, string $secretKey, string $auxRand): string
    {
        $n = Secp256k1::order();
        $d = gmp_init($secretKey, 16);
        $publicKey = Secp256k1::multiplyGenerator($d);
        // x-only keys stand for the point with an even y: negate d when P's y is odd.
        if ("\x03" === $publicKey[0]) {
            $d = $n - $d;
        }

        $xOnly = substr($publicKey, 1);
        $t = self::bytes32($d) ^ Secp256k1::taggedHash('BIP0340/aux', $auxRand);
        $k = gmp_mod(gmp_import(Secp256k1::taggedHash('BIP0340/nonce', $t.$xOnly.$message)), $n);
        if (0 === gmp_sign($k)) {
            throw new \RuntimeException('nonce is zero');
        }

        $r = Secp256k1::multiplyGenerator($k);
        if ("\x03" === $r[0]) {
            $k = $n - $k;
        }

        $rX = substr($r, 1);
        $e = gmp_mod(gmp_import(Secp256k1::taggedHash('BIP0340/challenge', $rX.$xOnly.$message)), $n);

        return $rX.self::bytes32(gmp_mod($k + $e * $d, $n));
    }

    private static function bytes32(\GMP $value): string
    {
        return str_pad(gmp_export($value), 32, "\0", STR_PAD_LEFT);
    }
}
