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
 * The Bitcoin network a payment request is for, from the currency in its prefix.
 *
 * The value is that currency code: "bc" in "lnbc2500u1...".
 */
enum Network: string
{
    case Mainnet = 'bc';
    case Testnet = 'tb';
    case Signet = 'tbs';
    case Regtest = 'bcrt';

    /**
     * The human-readable part of segwit addresses on this network.
     *
     * Signet shares "tb" with testnet: the addresses look the same, but the
     * coins on one network do not exist on the other.
     */
    public function segwitPrefix(): string
    {
        return match ($this) {
            self::Mainnet => 'bc',
            self::Testnet, self::Signet => 'tb',
            self::Regtest => 'bcrt',
        };
    }

    /**
     * The base58 version byte of pay-to-public-key-hash addresses.
     */
    public function p2pkhVersion(): int
    {
        return self::Mainnet === $this ? 0x00 : 0x6F;
    }

    /**
     * The base58 version byte of pay-to-script-hash addresses.
     */
    public function p2shVersion(): int
    {
        return self::Mainnet === $this ? 0x05 : 0xC4;
    }
}
