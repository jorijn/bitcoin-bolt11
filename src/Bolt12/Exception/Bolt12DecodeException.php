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

use Jorijn\Bitcoin\Bolt11\Exception\ExceptionInterface;

/**
 * Thrown for every BOLT #12 string that cannot be decoded, so one catch is
 * enough for untrusted input. The subclasses say what was wrong with it.
 *
 * It implements the same ExceptionInterface as the BOLT #11 exceptions, so
 * catching that interface covers everything this package throws.
 */
abstract class Bolt12DecodeException extends \RuntimeException implements ExceptionInterface {}
