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

namespace Tests\Jorijn\Bitcoin\Bolt11\Internal;

use Jorijn\Bitcoin\Bolt11\Internal\Secp256k1;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The spec vectors already exercise recovery end to end; these cover the
 * edges that no real invoice reaches.
 *
 * @internal
 */
#[CoversClass(Secp256k1::class)]
final class Secp256k1Test extends TestCase
{
    /** From the breakdown of the first example in BOLT #11. */
    private const HASH = '6daf4d488be41ce7cbb487cab1ef2975e5efcea879b20d421f0ef86b07cbb987';
    private const SIGNATURE = '8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d81127425e434ca29929406c23bba1ae8ac6ca32880b38d4bf6ff874024cac34ba9625f1';
    private const HIGH_S_SIGNATURE = '8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d8112742a1bcb35d66d6bf93dc445e51753935cc32a3a411efd8a7c7bd85b25815a01b50';
    private const PUBLIC_KEY = '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad';
    private const PRIVATE_KEY = 'e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734';

    private const P = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F';
    private const N = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';

    public function testRecoversAndVerifiesTheSpecExample(): void
    {
        $hash = self::bin(self::HASH);
        $signature = self::bin(self::SIGNATURE);

        self::assertSame(self::PUBLIC_KEY, bin2hex(Secp256k1::recoverPublicKey($hash, $signature, 1)));
        self::assertTrue(Secp256k1::verify($hash, $signature, self::bin(self::PUBLIC_KEY)));
        self::assertTrue(Secp256k1::isLowS($signature));

        // The other parity is another valid R, so it yields another key that
        // the signature verifies against too. That is why the recovery id is
        // part of the signature: without it, the payee would be ambiguous.
        $other = Secp256k1::recoverPublicKey($hash, $signature, 0);
        self::assertNotSame(self::PUBLIC_KEY, bin2hex($other));
        self::assertTrue(Secp256k1::verify($hash, $signature, $other));
        self::assertFalse(Secp256k1::verify(hash('sha256', 'another message', true), $signature, $other));
    }

    public function testHighSSignatures(): void
    {
        $hash = self::bin(self::HASH);
        $highS = self::bin(self::HIGH_S_SIGNATURE);

        self::assertFalse(Secp256k1::isLowS($highS));
        self::assertFalse(Secp256k1::isLowS('too short'));

        // s and n − s both verify: negating s negates R, so flipping the
        // recovery parity gives the original key back.
        self::assertTrue(Secp256k1::verify($hash, $highS, self::bin(self::PUBLIC_KEY)));
        self::assertSame(self::PUBLIC_KEY, bin2hex(Secp256k1::recoverPublicKey($hash, $highS, 0)));
    }

    public function testDerivesPublicKeys(): void
    {
        self::assertSame('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', bin2hex(Secp256k1::multiplyGenerator(gmp_init(1))));
        self::assertSame(self::PUBLIC_KEY, bin2hex(Secp256k1::multiplyGenerator(gmp_init(self::PRIVATE_KEY, 16))));
        self::assertSame(0, gmp_cmp(gmp_init(self::N, 16), Secp256k1::order()));

        $this->expectException(\InvalidArgumentException::class);
        Secp256k1::multiplyGenerator(Secp256k1::order());
    }

    /**
     * Recovery ids 2 and 3 mean R's x is r + n. That happens for about one
     * signature in 2^128, so build one: any point with x ≥ n, and r = x − n.
     * Recovering and then verifying must agree.
     */
    public function testRecoveryIdsForRAboveTheOrder(): void
    {
        $p = gmp_init(self::P, 16);
        $n = gmp_init(self::N, 16);
        $x = $n + 1;
        // Euler's criterion: x³ + 7 is a square, so there is a point with this x.
        while (0 !== gmp_cmp(gmp_powm($x * $x * $x + 7, gmp_div_q($p - 1, 2), $p), 1)) {
            ++$x;
        }

        $r = $x - $n;
        $signature = self::pad($r).self::pad(gmp_init(12345));
        $hash = hash('sha256', 'recovery id 2', true);

        foreach ([2, 3] as $recoveryId) {
            $publicKey = Secp256k1::recoverPublicKey($hash, $signature, $recoveryId);
            self::assertTrue(Secp256k1::verify($hash, $signature, $publicKey));
        }
    }

    #[DataProvider('provideRejectsUnrecoverableSignaturesCases')]
    public function testRejectsUnrecoverableSignatures(string $signature, int $recoveryId): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Secp256k1::recoverPublicKey(self::bin(self::HASH), $signature, $recoveryId);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideRejectsUnrecoverableSignaturesCases(): iterable
    {
        $valid = self::bin(self::SIGNATURE);
        $n = gmp_init(self::N, 16);
        $p = gmp_init(self::P, 16);

        yield 'r is zero' => [str_repeat("\0", 32).substr($valid, 32), 1];

        yield 's is zero' => [substr($valid, 0, 32).str_repeat("\0", 32), 1];

        yield 'r is n' => [self::pad($n).substr($valid, 32), 1];

        yield 's is n' => [substr($valid, 0, 32).self::pad($n), 1];

        yield 'signature of 63 bytes' => [substr($valid, 1), 1];

        yield 'recovery id 4' => [$valid, 4];

        yield 'negative recovery id' => [$valid, -1];

        // x = r + n would be p, which is outside the field.
        yield 'r + n is not below p' => [self::pad($p - $n).substr($valid, 32), 2];

        // No point on secp256k1 has x = 5: 5³ + 7 = 132 is not a square mod p.
        yield 'R is not on the curve' => [self::pad(gmp_init(5)).substr($valid, 32), 0];
    }

    #[DataProvider('provideRejectsInvalidPublicKeysCases')]
    public function testRejectsInvalidPublicKeys(string $publicKey): void
    {
        self::assertFalse(Secp256k1::isValidPublicKey($publicKey));
        self::assertFalse(Secp256k1::verify(self::bin(self::HASH), self::bin(self::SIGNATURE), $publicKey));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRejectsInvalidPublicKeysCases(): iterable
    {
        $x = substr(self::bin(self::PUBLIC_KEY), 1);

        yield 'uncompressed prefix' => ["\x04".$x];

        yield '32 bytes' => [$x];

        yield 'x is p' => ["\x02".self::pad(gmp_init(self::P, 16))];

        yield 'x is not on the curve' => ["\x02".self::pad(gmp_init(5))];

        yield 'empty' => [''];
    }

    public function testVerifyRejectsMalformedSignatures(): void
    {
        $publicKey = self::bin(self::PUBLIC_KEY);

        self::assertTrue(Secp256k1::isValidPublicKey($publicKey));
        self::assertFalse(Secp256k1::verify(self::bin(self::HASH), 'not a signature', $publicKey));
        self::assertFalse(Secp256k1::verify(self::bin(self::HASH), str_repeat("\0", 64), $publicKey));
        self::assertFalse(Secp256k1::verify(hash('sha256', 'another message', true), self::bin(self::SIGNATURE), $publicKey));
    }

    private static function bin(string $hex): string
    {
        return (string) hex2bin($hex);
    }

    private static function pad(\GMP $value): string
    {
        return str_pad(gmp_export($value), 32, "\0", STR_PAD_LEFT);
    }
}
