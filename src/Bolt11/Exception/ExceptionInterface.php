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
 * Implemented by every exception this library throws, for BOLT #11 and
 * BOLT #12 alike, so one catch covers all untrusted input.
 */
interface ExceptionInterface extends \Throwable {}
