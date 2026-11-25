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

namespace Jorijn\Bitcoin\Bolt11;

use Jorijn\Bitcoin\Bolt11\Exception\PaymentRequestDecodeException;
use Jorijn\Bitcoin\Bolt11\Model\PaymentRequest;

/**
 * Type against this interface to swap the decoder in tests, or to decorate it
 * (with a cache, say) without extending the final PaymentRequestDecoder.
 */
interface PaymentRequestDecoderInterface
{
    /**
     * Decodes a BOLT #11 payment request and verifies its signature.
     *
     * @param string $paymentRequest the invoice, "lnbc..." in lower or upper case
     *
     * @throws PaymentRequestDecodeException for every payment request that is not valid
     */
    public function decode(string $paymentRequest): PaymentRequest;
}
