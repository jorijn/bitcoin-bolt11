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

namespace Jorijn\Bitcoin\Bolt11\Model;

/**
 * A tagged field this library does not interpret. BOLT #11 lets readers skip
 * them, so newer invoices stay readable; they are kept here as raw 5-bit words.
 */
final readonly class UnknownField
{
    /**
     * @param int       $type  the 5-bit field type
     * @param list<int> $words the field data as 5-bit values
     */
    public function __construct(
        private int $type,
        private array $words,
    ) {}

    public function getType(): int
    {
        return $this->type;
    }

    /**
     * @return list<int>
     */
    public function getWords(): array
    {
        return $this->words;
    }

    /**
     * @return array{type: int, words: list<int>}
     */
    public function toArray(): array
    {
        return ['type' => $this->type, 'words' => $this->words];
    }
}
