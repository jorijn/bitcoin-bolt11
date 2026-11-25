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

namespace Jorijn\Bitcoin\Bolt11\Exception;

/**
 * The payment request requires a feature (an even bit in the `9` field) that
 * this library does not know, or misses a feature that another one depends on.
 * BOLT #11 says a reader must not pay it.
 */
final class UnknownRequiredFeatureException extends PaymentRequestDecodeException
{
    /**
     * @param list<int> $featureBits the bits that caused the rejection
     */
    public function __construct(string $message, private readonly array $featureBits)
    {
        parent::__construct($message);
    }

    /**
     * @return list<int>
     */
    public function getFeatureBits(): array
    {
        return $this->featureBits;
    }
}
