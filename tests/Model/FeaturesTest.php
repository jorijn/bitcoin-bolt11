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

namespace Tests\Jorijn\Bitcoin\Bolt11\Model;

use Jorijn\Bitcoin\Bolt11\Model\Features;
use Jorijn\Bitcoin\Bolt11\Model\Network;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(Features::class)]
#[CoversClass(Network::class)]
final class FeaturesTest extends TestCase
{
    public function testRequiredAndOptionalBits(): void
    {
        // payment_secret required (14), basic_mpp optional (17), unknown 99 and 100.
        $features = new Features([100, 17, 14, 99, 14]);

        self::assertSame([14, 17, 99, 100], $features->getBits());
        self::assertTrue($features->hasBit(17));
        self::assertFalse($features->hasBit(16));

        self::assertTrue($features->supports(Features::PAYMENT_SECRET));
        self::assertTrue($features->requires(Features::PAYMENT_SECRET));
        self::assertTrue($features->supports(Features::BASIC_MPP));
        self::assertTrue($features->supports(Features::BASIC_MPP + 1));
        self::assertFalse($features->requires(Features::BASIC_MPP));
        self::assertFalse($features->supports(Features::PAYMENT_METADATA));

        self::assertSame([100], $features->getUnknownRequiredBits());
        self::assertSame([], (new Features())->getBits());
    }

    public function testNetworkAddressParameters(): void
    {
        self::assertSame(Network::Signet, Network::from('tbs'));
        self::assertSame('tb', Network::Signet->segwitPrefix());
        self::assertSame('bcrt', Network::Regtest->segwitPrefix());
        self::assertSame('bc', Network::Mainnet->segwitPrefix());
        self::assertSame(0x00, Network::Mainnet->p2pkhVersion());
        self::assertSame(0x05, Network::Mainnet->p2shVersion());
        self::assertSame(0x6F, Network::Regtest->p2pkhVersion());
        self::assertSame(0xC4, Network::Testnet->p2shVersion());
    }
}
