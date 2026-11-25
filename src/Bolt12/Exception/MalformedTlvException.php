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
 * The bytes are not a valid TLV stream, or a field does not have the length
 * or layout its type requires (a truncated blinded path, say).
 */
final class MalformedTlvException extends Bolt12DecodeException {}
