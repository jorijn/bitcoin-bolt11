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
 * The message is well-formed but breaks a rule the specification sets for
 * readers: a required field is missing, a field is out of range, a string is
 * not valid UTF-8, or fields contradict each other.
 */
final class InvalidFieldException extends Bolt12DecodeException {}
