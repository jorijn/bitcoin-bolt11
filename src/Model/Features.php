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

namespace Jorijn\Bitcoin\Bolt11\Model;

/**
 * The feature bits of a payment request (`9` field), as defined in BOLT #9.
 *
 * Features come in pairs: the even bit means the payee requires the feature,
 * the odd bit (even + 1) that it supports it. The constants are the even bit.
 */
final readonly class Features
{
    public const VAR_ONION_OPTIN = 8;
    public const PAYMENT_SECRET = 14;
    public const BASIC_MPP = 16;
    public const ROUTE_BLINDING = 24;
    public const ATTRIBUTION_DATA = 36;
    public const PAYMENT_METADATA = 48;

    /**
     * Features BOLT #9 allows in the `9` field of an invoice. In strict mode,
     * any other even bit makes the decoder reject the invoice.
     */
    public const KNOWN = [
        self::VAR_ONION_OPTIN,
        self::PAYMENT_SECRET,
        self::BASIC_MPP,
        self::ROUTE_BLINDING,
        self::ATTRIBUTION_DATA,
        self::PAYMENT_METADATA,
    ];

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
     * @return list<int> the numbers of the bits that are set, ascending
     */
    public function getBits(): array
    {
        return $this->bits;
    }

    /**
     * Whether this exact bit is set.
     */
    public function hasBit(int $bit): bool
    {
        return \in_array($bit, $this->bits, true);
    }

    /**
     * Whether the payee supports a feature, as optional or as required.
     *
     * @param int $feature either bit of the pair, for example Features::BASIC_MPP
     */
    public function supports(int $feature): bool
    {
        $even = $feature & ~1;

        return $this->hasBit($even) || $this->hasBit($even + 1);
    }

    /**
     * Whether the payee requires a feature: a payer that lacks it must not pay.
     *
     * @param int $feature either bit of the pair, for example Features::PAYMENT_SECRET
     */
    public function requires(int $feature): bool
    {
        return $this->hasBit($feature & ~1);
    }

    /**
     * Even bits that are set but not in KNOWN.
     *
     * @return list<int>
     */
    public function getUnknownRequiredBits(): array
    {
        return array_values(array_filter(
            $this->bits,
            static fn (int $bit): bool => 0 === $bit % 2 && !\in_array($bit, self::KNOWN, true),
        ));
    }
}
