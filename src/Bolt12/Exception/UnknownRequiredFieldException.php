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
 * The message has a field with an even type this library does not know.
 * "It is OK to be odd": unknown odd fields are skipped, but an even one means
 * the writer requires the reader to understand it, so it must be rejected.
 */
final class UnknownRequiredFieldException extends Bolt12DecodeException
{
    public function __construct(string $message, private readonly int $type)
    {
        parent::__construct($message);
    }

    public function getType(): int
    {
        return $this->type;
    }
}
