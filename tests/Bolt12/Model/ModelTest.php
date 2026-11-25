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

namespace Tests\Jorijn\Bitcoin\Bolt12\Model;

use Jorijn\Bitcoin\Bolt11\Model\Network;
use Jorijn\Bitcoin\Bolt12\Model\BlindedHop;
use Jorijn\Bitcoin\Bolt12\Model\BlindedPath;
use Jorijn\Bitcoin\Bolt12\Model\Chain;
use Jorijn\Bitcoin\Bolt12\Model\Features;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(Chain::class)]
#[CoversClass(Features::class)]
#[CoversClass(BlindedPath::class)]
#[UsesClass(BlindedHop::class)]
#[UsesClass(Network::class)]
final class ModelTest extends TestCase
{
    public function testChainHashesAreGenesisHashesReversed(): void
    {
        // Explorers show the genesis hash in the other byte order.
        self::assertSame('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f', bin2hex(strrev((string) hex2bin(Chain::BITCOIN))));
        self::assertSame('00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043', bin2hex(strrev((string) hex2bin(Chain::TESTNET4))));

        self::assertSame(Network::Mainnet, Chain::toNetwork(Chain::BITCOIN));
        self::assertSame(Network::Mainnet, Chain::toNetwork(strtoupper(Chain::BITCOIN)));
        self::assertSame(Network::Testnet, Chain::toNetwork(Chain::TESTNET3));
        self::assertSame(Network::Testnet, Chain::toNetwork(Chain::TESTNET4));
        self::assertSame(Network::Signet, Chain::toNetwork(Chain::SIGNET));
        self::assertSame(Network::Regtest, Chain::toNetwork(Chain::REGTEST));
        self::assertNull(Chain::toNetwork('1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003'), 'Liquid');
    }

    public function testFeatures(): void
    {
        $features = Features::fromBytes("\x02\x01\x00");

        self::assertSame([8, 17], $features->getBits());
        self::assertTrue($features->hasBit(17));
        self::assertTrue($features->supports(Features::MPP));
        self::assertFalse($features->requires(Features::MPP));
        self::assertSame([8], $features->getUnknownRequiredBits());
        self::assertSame([], $features->getUnknownRequiredBits([8]));
        self::assertSame([], Features::fromBytes('')->getBits());
        self::assertSame([1, 3], (new Features([3, 1, 3]))->getBits());
    }

    public function testBlindedPathWithANodeId(): void
    {
        $key = '02'.str_repeat('11', 32);
        $path = new BlindedPath($key, '03'.str_repeat('22', 32), [new BlindedHop('02'.str_repeat('33', 32), ''), new BlindedHop('02'.str_repeat('44', 32), 'ff')]);

        self::assertSame($key, $path->getIntroductionNodeId());
        self::assertNull($path->getIntroductionShortChannelId());
        self::assertNull($path->getIntroductionDirection());
        self::assertSame('02'.str_repeat('44', 32), $path->getFinalBlindedNodeId());
        self::assertCount(2, $path->toArray()['hops']);
    }
}
