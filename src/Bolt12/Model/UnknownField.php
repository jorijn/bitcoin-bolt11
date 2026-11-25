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

namespace Jorijn\Bitcoin\Bolt12\Model;

/**
 * A TLV record this library does not interpret. "It is OK to be odd": readers
 * skip unknown odd types, so newer messages stay readable. The record is kept
 * so it can be inspected or passed on unchanged.
 */
final readonly class UnknownField
{
    /**
     * @param int    $type  the TLV type
     * @param string $value the value, hex encoded
     */
    public function __construct(
        private int $type,
        private string $value,
    ) {}

    public function getType(): int
    {
        return $this->type;
    }

    /**
     * The value, hex encoded.
     */
    public function getValue(): string
    {
        return $this->value;
    }

    /**
     * @return array{type: int, value: string}
     */
    public function toArray(): array
    {
        return ['type' => $this->type, 'value' => $this->value];
    }
}
