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
 * A way to pay an invoice: a blinded path (from invoice_paths) with the fees
 * and limits for paying through it (the matching entry of invoice_blindedpay).
 * The specification keeps them in two lists of equal length; this class pairs
 * them so they cannot be mixed up.
 *
 * @phpstan-import-type BlindedPathArray from BlindedPath
 *
 * @phpstan-type PaymentPathArray array{path: BlindedPathArray, fee_base_msat: int, fee_proportional_millionths: int, cltv_expiry_delta: int, htlc_minimum_msat: int, htlc_maximum_msat: int, features: list<int>}
 */
final readonly class PaymentPath
{
    /**
     * @param int $htlcMaximumMsat values above PHP_INT_MAX (more than all bitcoin there will ever be) are capped at PHP_INT_MAX
     */
    public function __construct(
        private BlindedPath $path,
        private int $feeBaseMsat,
        private int $feeProportionalMillionths,
        private int $cltvExpiryDelta,
        private int $htlcMinimumMsat,
        private int $htlcMaximumMsat,
        private Features $features,
    ) {}

    public function getPath(): BlindedPath
    {
        return $this->path;
    }

    /**
     * The fee for the whole blinded part of the route, in millisatoshis.
     */
    public function getFeeBaseMsat(): int
    {
        return $this->feeBaseMsat;
    }

    public function getFeeProportionalMillionths(): int
    {
        return $this->feeProportionalMillionths;
    }

    public function getCltvExpiryDelta(): int
    {
        return $this->cltvExpiryDelta;
    }

    public function getHtlcMinimumMsat(): int
    {
        return $this->htlcMinimumMsat;
    }

    public function getHtlcMaximumMsat(): int
    {
        return $this->htlcMaximumMsat;
    }

    public function getFeatures(): Features
    {
        return $this->features;
    }

    /**
     * Whether a payer may use this path: not when its features require
     * something this library does not know. An invoice is only rejected when
     * none of its paths is usable.
     */
    public function isUsable(): bool
    {
        return [] === $this->features->getUnknownRequiredBits();
    }

    /**
     * @return PaymentPathArray
     */
    public function toArray(): array
    {
        return [
            'path' => $this->path->toArray(),
            'fee_base_msat' => $this->feeBaseMsat,
            'fee_proportional_millionths' => $this->feeProportionalMillionths,
            'cltv_expiry_delta' => $this->cltvExpiryDelta,
            'htlc_minimum_msat' => $this->htlcMinimumMsat,
            'htlc_maximum_msat' => $this->htlcMaximumMsat,
            'features' => $this->features->getBits(),
        ];
    }
}
