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

namespace Jorijn\Bitcoin\Bolt11\Network;

use BitWasp\Bitcoin\Network\Networks\BitcoinRegtest as BitWaspBitcoinRegtest;

/**
 * Bitcoin regtest, the network of `lnbcrt` invoices.
 *
 * bitwasp/bitcoin has a regtest network, but it inherits the testnet bech32
 * prefix `tb`, while Bitcoin Core uses `bcrt` on regtest. Fallback addresses
 * would come out as tb1... addresses that a regtest node rejects. This class
 * only corrects that prefix, so `instanceof` checks against the bitwasp class
 * keep working.
 */
class BitcoinRegtest extends BitWaspBitcoinRegtest
{
    /** @var array<string, string> */
    protected $bech32PrefixMap = [
        self::BECH32_PREFIX_SEGWIT => 'bcrt',
    ];
}
