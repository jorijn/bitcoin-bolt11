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
 * The payment request breaks a rule of BOLT #11 that has no more specific exception.
 */
final class InvalidPaymentRequestException extends PaymentRequestDecodeException {}
