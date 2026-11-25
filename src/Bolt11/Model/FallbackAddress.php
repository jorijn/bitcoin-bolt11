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
 * An on-chain address to pay to when the Lightning payment fails (`f` field).
 */
final readonly class FallbackAddress
{
    public const VERSION_P2PKH = 17;
    public const VERSION_P2SH = 18;

    /**
     * @param int    $version 0 to 16 for a segwit witness version, 17 for P2PKH, 18 for P2SH
     * @param string $program hex: the witness program, or the 20-byte hash for P2PKH and P2SH
     * @param string $address the address in the form a wallet shows it
     */
    public function __construct(
        private int $version,
        private string $program,
        private string $address,
    ) {}

    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * The witness program or hash, hex encoded.
     */
    public function getProgram(): string
    {
        return $this->program;
    }

    public function getAddress(): string
    {
        return $this->address;
    }

    public function isSegwit(): bool
    {
        return $this->version <= 16;
    }

    /**
     * @return array{version: int, program: string, address: string}
     */
    public function toArray(): array
    {
        return ['version' => $this->version, 'program' => $this->program, 'address' => $this->address];
    }
}
