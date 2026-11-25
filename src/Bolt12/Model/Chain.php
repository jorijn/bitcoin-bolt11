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

use Jorijn\Bitcoin\Bolt11\Model\Network;

/**
 * Chain hashes as BOLT #12 writes them: the genesis block hash in the byte
 * order Bitcoin uses internally, the reverse of how explorers show it.
 */
final class Chain
{
    public const BITCOIN = '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000';
    public const TESTNET3 = '43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000';
    public const TESTNET4 = '43f08bdab050e35b567c864b91f47f50ae725ae2de53bcfbbaf284da00000000';
    public const SIGNET = 'f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000';
    public const REGTEST = '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f';

    private function __construct() {}

    /**
     * The BOLT #11 network for a chain hash, or null for a chain that is not
     * Bitcoin (Liquid, say). Testnet3 and testnet4 both map to Testnet, as
     * BOLT #11 has one prefix ("tb") for every test network.
     *
     * @param string $chainHash hex, as returned by getChains() and getChain()
     */
    public static function toNetwork(string $chainHash): ?Network
    {
        return match (strtolower($chainHash)) {
            self::BITCOIN => Network::Mainnet,
            self::TESTNET3, self::TESTNET4 => Network::Testnet,
            self::SIGNET => Network::Signet,
            self::REGTEST => Network::Regtest,
            default => null,
        };
    }
}
