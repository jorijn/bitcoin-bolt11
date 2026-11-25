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
 * The text is not a BOLT #12 string: invalid characters, mixed case, a stray
 * "+", bad padding, or a prefix other than the one expected.
 */
final class InvalidEncodingException extends Bolt12DecodeException {}
