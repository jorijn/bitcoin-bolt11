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

namespace Jorijn\Bitcoin\Bolt12\Model;

/**
 * A BOLT #12 features field (offer_features, invreq_features,
 * invoice_features or the features of a blinded_payinfo).
 *
 * Features come in pairs: the even bit means the writer requires the
 * feature, the odd bit (even + 1) that it supports it.
 */
final readonly class Features
{
    /** Invoice feature: the payer must (16) or may (17) split the payment over several paths. */
    public const MPP = 16;

    /** @var list<int> */
    private array $bits;

    /**
     * @param list<int> $bits the numbers of the bits that are set
     */
    public function __construct(array $bits = [])
    {
        $bits = array_values(array_unique($bits));
        sort($bits);
        $this->bits = $bits;
    }

    /**
     * Reads a features bitmap: big-endian, bit 0 is the lowest bit of the last byte.
     */
    public static function fromBytes(string $bytes): self
    {
        $bits = [];
        $length = \strlen($bytes);
        for ($i = 0; $i < $length; ++$i) {
            $byte = \ord($bytes[$length - 1 - $i]);
            for ($bit = 0; $bit < 8; ++$bit) {
                if (0 !== ($byte & (1 << $bit))) {
                    $bits[] = $i * 8 + $bit;
                }
            }
        }

        return new self($bits);
    }

    /**
     * @return list<int> the numbers of the bits that are set, ascending
     */
    public function getBits(): array
    {
        return $this->bits;
    }

    public function hasBit(int $bit): bool
    {
        return \in_array($bit, $this->bits, true);
    }

    /**
     * Whether the writer supports a feature, as optional or as required.
     *
     * @param int $feature either bit of the pair, for example Features::MPP
     */
    public function supports(int $feature): bool
    {
        $even = $feature & ~1;

        return $this->hasBit($even) || $this->hasBit($even + 1);
    }

    /**
     * Whether the writer requires a feature.
     *
     * @param int $feature either bit of the pair, for example Features::MPP
     */
    public function requires(int $feature): bool
    {
        return $this->hasBit($feature & ~1);
    }

    /**
     * Even bits that are set but not in $known.
     *
     * @param list<int> $known the even bits the reader understands
     *
     * @return list<int>
     */
    public function getUnknownRequiredBits(array $known = []): array
    {
        return array_values(array_filter(
            $this->bits,
            static fn (int $bit): bool => 0 === $bit % 2 && !\in_array($bit, $known, true),
        ));
    }
}
