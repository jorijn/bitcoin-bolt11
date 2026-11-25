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

use BitWasp\Bitcoin\Network\Network;
use BitWasp\Bitcoin\Script\ScriptType;

/**
 * Bitcoin signet, the network of `lntbs` invoices. bitwasp/bitcoin has no signet
 * network of its own.
 *
 * Signet uses the same address prefixes as testnet, so on-chain addresses look
 * identical. It deliberately extends Network rather than BitcoinTestnet: an
 * `instanceof BitcoinTestnet` check must not mistake a signet invoice for a
 * testnet one, because funds on one network do not exist on the other.
 */
class BitcoinSignet extends Network
{
    /** @var array<string, string> */
    protected $base58PrefixMap = [
        self::BASE58_ADDRESS_P2PKH => '6f',
        self::BASE58_ADDRESS_P2SH => 'c4',
        self::BASE58_WIF => 'ef',
    ];

    /** @var array<string, string> */
    protected $bech32PrefixMap = [
        self::BECH32_PREFIX_SEGWIT => 'tb',
    ];

    /** @var array<string, string> */
    protected $bip32PrefixMap = [
        self::BIP32_PREFIX_XPUB => '043587cf',
        self::BIP32_PREFIX_XPRV => '04358394',
    ];

    /** @var array<string, string> */
    protected $bip32ScriptTypeMap = [
        self::BIP32_PREFIX_XPUB => ScriptType::P2PKH,
        self::BIP32_PREFIX_XPRV => ScriptType::P2PKH,
    ];

    protected $signedMessagePrefix = 'Bitcoin Signed Message';

    /**
     * Message start of the default signet (0a03cf40 on the wire), stored
     * byte-reversed like bitwasp/bitcoin does for its own networks.
     */
    protected $p2pMagic = '40cf030a';
}
