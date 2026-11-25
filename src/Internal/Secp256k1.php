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
 * ECDSA public-key recovery and verification on secp256k1, with ext-gmp.
 *
 * Not constant-time, and that is deliberate: this class only ever handles
 * public data (an invoice's signature and the payee's public key), so there is
 * no secret whose timing could leak. Do not use it to sign anything.
 *
 * Points are kept in Jacobian coordinates (X, Y, Z with x = X/Z², y = Y/Z³)
 * while multiplying, so a whole scalar multiplication needs one modular
 * inversion instead of one per step.
 *
 * @internal not covered by the backward compatibility promise
 *
 * @phpstan-type AffinePoint array{\GMP, \GMP}
 * @phpstan-type JacobianPoint array{\GMP, \GMP, \GMP}
 */
final class Secp256k1
{
    private static ?self $instance = null;

    /** The field prime. */
    private readonly \GMP $p;

    /** The group order. */
    private readonly \GMP $n;

    /** n / 2, the largest s that is still "low S" (BIP 62, BOLT #11). */
    private readonly \GMP $halfN;

    /** (p + 1) / 4: p ≡ 3 (mod 4), so a square root is a single exponentiation. */
    private readonly \GMP $sqrtExponent;

    /** @var AffinePoint */
    private readonly array $generator;

    private function __construct()
    {
        $this->p = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16);
        $this->n = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
        $this->halfN = gmp_div_q($this->n, 2);
        $this->sqrtExponent = gmp_div_q($this->p + 1, 4);
        $this->generator = [
            gmp_init('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16),
            gmp_init('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16),
        ];
    }

    /**
     * Recovers the compressed public key that made a signature.
     *
     * @param string $hash       32-byte message hash
     * @param string $signature  64 bytes: r || s
     * @param int    $recoveryId 0 to 3: bit 0 is the parity of R's y, bit 1 says R's x is r + n
     *
     * @return string 33-byte compressed public key
     *
     * @throws \InvalidArgumentException when no public key can be recovered
     */
    public static function recoverPublicKey(string $hash, string $signature, int $recoveryId): string
    {
        $curve = self::instance();
        [$r, $s] = $curve->parseSignature($signature);
        if ($recoveryId < 0 || $recoveryId > 3) {
            throw new \InvalidArgumentException('recovery id must be between 0 and 3');
        }

        // R is the point k·G the signer used; its x coordinate is r, or r + n
        // when that still fits in the field (bit 1 of the recovery id).
        $x = $r + ($recoveryId >> 1) * $curve->n;
        if (gmp_cmp($x, $curve->p) >= 0) {
            throw new \InvalidArgumentException('signature R is not a point on the curve');
        }

        $point = $curve->liftX($x, 1 === ($recoveryId & 1));
        if (null === $point) {
            throw new \InvalidArgumentException('signature R is not a point on the curve');
        }

        // Q = r⁻¹ · (s·R − e·G), computed as (−e·r⁻¹)·G + (s·r⁻¹)·R.
        $rInverse = $curve->invert($r, $curve->n);
        $e = gmp_import($hash);
        $publicKey = $curve->multiplyAndAdd(
            $curve->mod(-$e * $rInverse, $curve->n),
            $curve->generator,
            $curve->mod($s * $rInverse, $curve->n),
            $point,
        );

        if (null === $publicKey) {
            throw new \InvalidArgumentException('recovered public key is the point at infinity');
        }

        return $curve->compress($publicKey);
    }

    /**
     * Verifies an ECDSA signature against a known public key. High-S
     * signatures verify as well; check isLowS() separately where it matters.
     *
     * @param string $hash      32-byte message hash
     * @param string $signature 64 bytes: r || s
     * @param string $publicKey 33-byte compressed public key
     */
    public static function verify(string $hash, string $signature, string $publicKey): bool
    {
        $curve = self::instance();

        try {
            [$r, $s] = $curve->parseSignature($signature);
        } catch (\InvalidArgumentException) {
            return false;
        }

        $point = $curve->decompress($publicKey);
        if (null === $point) {
            return false;
        }

        // u1·G + u2·Q must have r as its x coordinate (mod n).
        $sInverse = $curve->invert($s, $curve->n);
        $result = $curve->multiplyAndAdd(
            $curve->mod(gmp_import($hash) * $sInverse, $curve->n),
            $curve->generator,
            $curve->mod($r * $sInverse, $curve->n),
            $point,
        );

        return null !== $result && 0 === gmp_cmp($curve->mod($result[0], $curve->n), $r);
    }

    /**
     * Whether s is at most n/2. For every signature (r, s), (r, n − s) is
     * valid too; requiring the low one makes signatures non-malleable.
     *
     * @param string $signature 64 bytes: r || s
     */
    public static function isLowS(string $signature): bool
    {
        return 64 === \strlen($signature)
            && gmp_cmp(gmp_import(substr($signature, 32)), self::instance()->halfN) <= 0;
    }

    /**
     * Whether these 33 bytes are a compressed public key on the curve.
     */
    public static function isValidPublicKey(string $publicKey): bool
    {
        return null !== self::instance()->decompress($publicKey);
    }

    /**
     * k·G as a compressed public key. Only the tests use this, to sign invoices
     * with a known key; it is not constant-time, see the class comment.
     */
    public static function multiplyGenerator(\GMP $scalar): string
    {
        $curve = self::instance();
        $point = $curve->multiplyAndAdd($curve->mod($scalar, $curve->n), $curve->generator, gmp_init(0), $curve->generator);
        if (null === $point) {
            throw new \InvalidArgumentException('scalar is a multiple of the group order');
        }

        return $curve->compress($point);
    }

    public static function order(): \GMP
    {
        return self::instance()->n;
    }

    private static function instance(): self
    {
        return self::$instance ??= new self();
    }

    /**
     * @return array{\GMP, \GMP} r and s, both in [1, n − 1]
     */
    private function parseSignature(string $signature): array
    {
        if (64 !== \strlen($signature)) {
            throw new \InvalidArgumentException('signature must be 64 bytes');
        }

        $r = gmp_import(substr($signature, 0, 32));
        $s = gmp_import(substr($signature, 32));
        foreach ([$r, $s] as $value) {
            if (gmp_cmp($value, 0) <= 0 || gmp_cmp($value, $this->n) >= 0) {
                throw new \InvalidArgumentException('signature r or s is out of range');
            }
        }

        return [$r, $s];
    }

    /**
     * @return ?AffinePoint
     */
    private function decompress(string $publicKey): ?array
    {
        if (33 !== \strlen($publicKey) || ("\x02" !== $publicKey[0] && "\x03" !== $publicKey[0])) {
            return null;
        }

        $x = gmp_import(substr($publicKey, 1));
        if (gmp_cmp($x, $this->p) >= 0) {
            return null;
        }

        return $this->liftX($x, "\x03" === $publicKey[0]);
    }

    /**
     * The point with this x coordinate and y parity, if there is one.
     *
     * @return ?AffinePoint
     */
    private function liftX(\GMP $x, bool $odd): ?array
    {
        $rightHandSide = $this->mod($x * $x * $x + 7, $this->p);
        $y = gmp_powm($rightHandSide, $this->sqrtExponent, $this->p);

        // Half of all x values have no point: then y² is not y³ + 7.
        if (0 !== gmp_cmp($this->mod($y * $y, $this->p), $rightHandSide)) {
            return null;
        }

        if (gmp_testbit($y, 0) !== $odd) {
            $y = $this->p - $y;
        }

        return [$x, $y];
    }

    /**
     * @param AffinePoint $point
     */
    private function compress(array $point): string
    {
        return (gmp_testbit($point[1], 0) ? "\x03" : "\x02").str_pad(gmp_export($point[0]), 32, "\0", STR_PAD_LEFT);
    }

    /**
     * a·P + b·Q in one pass over the bits (Shamir's trick).
     *
     * @param AffinePoint $p
     * @param AffinePoint $q
     *
     * @return ?AffinePoint null for the point at infinity
     */
    private function multiplyAndAdd(\GMP $a, array $p, \GMP $b, array $q): ?array
    {
        $one = gmp_init(1);
        $jacobianP = [$p[0], $p[1], $one];
        $jacobianQ = [$q[0], $q[1], $one];
        $sum = $this->add($jacobianP, $jacobianQ);

        $result = null;
        for ($bit = max(\strlen(gmp_strval($a, 2)), \strlen(gmp_strval($b, 2))) - 1; $bit >= 0; --$bit) {
            $result = $this->double($result);
            $bitA = gmp_testbit($a, $bit);
            $bitB = gmp_testbit($b, $bit);
            if ($bitA && $bitB) {
                $result = $this->add($result, $sum);
            } elseif ($bitA) {
                $result = $this->add($result, $jacobianP);
            } elseif ($bitB) {
                $result = $this->add($result, $jacobianQ);
            }
        }

        if (null === $result) {
            return null;
        }

        $zInverse = $this->invert($result[2], $this->p);
        $zInverse2 = $this->mod($zInverse * $zInverse, $this->p);

        return [
            $this->mod($result[0] * $zInverse2, $this->p),
            $this->mod($result[1] * $zInverse2 * $zInverse, $this->p),
        ];
    }

    /**
     * Point doubling for a = 0 (secp256k1 is y² = x³ + 7).
     *
     * @param ?JacobianPoint $point
     *
     * @return ?JacobianPoint
     */
    private function double(?array $point): ?array
    {
        if (null === $point || 0 === gmp_sign($point[1])) {
            return null;
        }

        [$x, $y, $z] = $point;
        $yy = $this->mod($y * $y, $this->p);
        $s = $this->mod(4 * $x * $yy, $this->p);
        $m = $this->mod(3 * $x * $x, $this->p);
        $x3 = $this->mod($m * $m - 2 * $s, $this->p);

        return [
            $x3,
            $this->mod($m * ($s - $x3) - 8 * $yy * $yy, $this->p),
            $this->mod(2 * $y * $z, $this->p),
        ];
    }

    /**
     * @param ?JacobianPoint $first
     * @param ?JacobianPoint $second
     *
     * @return ?JacobianPoint
     */
    private function add(?array $first, ?array $second): ?array
    {
        if (null === $first) {
            return $second;
        }

        if (null === $second) {
            return $first;
        }

        [$x1, $y1, $z1] = $first;
        [$x2, $y2, $z2] = $second;
        $z1z1 = $this->mod($z1 * $z1, $this->p);
        $z2z2 = $this->mod($z2 * $z2, $this->p);
        $u1 = $this->mod($x1 * $z2z2, $this->p);
        $u2 = $this->mod($x2 * $z1z1, $this->p);
        $s1 = $this->mod($y1 * $z2 * $z2z2, $this->p);
        $s2 = $this->mod($y2 * $z1 * $z1z1, $this->p);

        if (0 === gmp_cmp($u1, $u2)) {
            // Same x: either the same point (double it) or each other's negation.
            return 0 === gmp_cmp($s1, $s2) ? $this->double($first) : null;
        }

        $h = $this->mod($u2 - $u1, $this->p);
        $r = $this->mod($s2 - $s1, $this->p);
        $hh = $this->mod($h * $h, $this->p);
        $hhh = $this->mod($h * $hh, $this->p);
        $v = $this->mod($u1 * $hh, $this->p);
        $x3 = $this->mod($r * $r - $hhh - 2 * $v, $this->p);

        return [
            $x3,
            $this->mod($r * ($v - $x3) - $s1 * $hhh, $this->p),
            $this->mod($h * $z1 * $z2, $this->p),
        ];
    }

    private function invert(\GMP $value, \GMP $modulus): \GMP
    {
        $inverse = gmp_invert($value, $modulus);
        if (false === $inverse) {
            throw new \InvalidArgumentException('value has no modular inverse');
        }

        return $inverse;
    }

    /**
     * A modulo that is never negative (gmp_mod already is, this names the intent).
     */
    private function mod(\GMP $value, \GMP $modulus): \GMP
    {
        return gmp_mod($value, $modulus);
    }
}
