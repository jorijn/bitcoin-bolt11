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

namespace Jorijn\Bitcoin\Bolt12\Exception;

/**
 * A features field sets an even bit this library does not know: the writer
 * requires a feature the reader lacks, so it must not use the message.
 */
final class UnknownRequiredFeatureException extends Bolt12DecodeException
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
