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
 * An on-chain segwit address to pay to instead (invoice_fallbacks).
 */
final readonly class FallbackAddress
{
    /**
     * @param int     $version 0 to 16, the witness version
     * @param string  $program hex, the witness program
     * @param ?string $address the address as a wallet shows it; null for a chain that is not Bitcoin
     */
    public function __construct(
        private int $version,
        private string $program,
        private ?string $address,
    ) {}

    public function getVersion(): int
    {
        return $this->version;
    }

    public function getProgram(): string
    {
        return $this->program;
    }

    public function getAddress(): ?string
    {
        return $this->address;
    }

    /**
     * @return array{version: int, program: string, address: ?string}
     */
    public function toArray(): array
    {
        return ['version' => $this->version, 'program' => $this->program, 'address' => $this->address];
    }
}
