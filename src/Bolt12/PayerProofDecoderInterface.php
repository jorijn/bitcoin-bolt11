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

namespace Jorijn\Bitcoin\Bolt12;

use Jorijn\Bitcoin\Bolt12\Exception\Bolt12DecodeException;
use Jorijn\Bitcoin\Bolt12\Model\PayerProof;

/**
 * Type against this interface to swap the decoder in tests, or to decorate it
 * without extending the final PayerProofDecoder.
 */
interface PayerProofDecoderInterface
{
    /**
     * Decodes a payer proof ("lnp1...") and verifies both its signatures and
     * its preimage.
     *
     * @throws Bolt12DecodeException for every string that is not a valid payer proof
     */
    public function decode(string $payerProof): PayerProof;
}
