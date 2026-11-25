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

use Jorijn\Bitcoin\Bolt11\Model\FallbackAddress;
use Jorijn\Bitcoin\Bolt11\Model\Features;
use Jorijn\Bitcoin\Bolt11\Model\Network;
use Jorijn\Bitcoin\Bolt11\Model\PaymentRequest;
use Jorijn\Bitcoin\Bolt11\Model\RouteHint;
use Jorijn\Bitcoin\Bolt11\Model\RouteHintHop;
use Jorijn\Bitcoin\Bolt11\Model\UnknownField;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(PaymentRequest::class)]
#[CoversClass(FallbackAddress::class)]
#[CoversClass(RouteHint::class)]
#[CoversClass(RouteHintHop::class)]
#[CoversClass(UnknownField::class)]
#[UsesClass(Features::class)]
#[UsesClass(Network::class)]
final class PaymentRequestTest extends TestCase
{
    private const DESCRIPTION = 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon';

    public function testSatoshisRoundDown(): void
    {
        self::assertSame(1, self::paymentRequest(milliSatoshis: 1999)->getSatoshis());
        self::assertSame(0, self::paymentRequest(milliSatoshis: 999)->getSatoshis());
        self::assertNull(self::paymentRequest(milliSatoshis: null)->getSatoshis());
    }

    public function testExpiry(): void
    {
        $paymentRequest = self::paymentRequest(expiry: 60);
        $expiresAt = $paymentRequest->getExpiresAt();

        self::assertSame(1496314718, $expiresAt->getTimestamp());
        self::assertSame('+00:00', $expiresAt->getTimezone()->getName());
        self::assertFalse($paymentRequest->isExpired(new \DateTimeImmutable('@1496314717')));
        self::assertTrue($paymentRequest->isExpired(new \DateTimeImmutable('@1496314718')));

        // Without a clock it uses the current time; 2017 is long gone.
        self::assertTrue($paymentRequest->isExpired());
    }

    public function testVerifyDescriptionHash(): void
    {
        $withHash = self::paymentRequest(descriptionHash: '3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1');

        self::assertTrue($withHash->verifyDescriptionHash(self::DESCRIPTION));
        self::assertFalse($withHash->verifyDescriptionHash(self::DESCRIPTION.' '));
        self::assertFalse(self::paymentRequest()->verifyDescriptionHash(self::DESCRIPTION));
    }

    public function testToArrayAndJson(): void
    {
        $paymentRequest = new PaymentRequest(
            prefix: 'lntbs2500u',
            network: Network::Signet,
            milliSatoshis: 250_000_000,
            timestamp: new \DateTimeImmutable('@1496314658'),
            payeeNodeKey: '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
            signature: str_repeat('ab', 64),
            recoveryFlag: 1,
            paymentHash: str_repeat('01', 32),
            paymentSecret: str_repeat('11', 32),
            description: 'coffee',
            expiry: 60,
            minFinalCltvExpiryDelta: 40,
            metadata: '01fafaf0',
            features: new Features([14, 8]),
            fallbackAddresses: [new FallbackAddress(0, '751e76e8199196d454941c45d1b3a323f1433bd6', 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')],
            routeHints: [new RouteHint([new RouteHintHop('02'.str_repeat('aa', 32), '0102030405060708', 1, 20, 3)])],
            unknownFields: [new UnknownField(10, [0, 0, 0])],
        );

        $expected = [
            'prefix' => 'lntbs2500u',
            'network' => 'tbs',
            'milli_satoshis' => 250_000_000,
            'satoshis' => 250_000,
            'timestamp' => 1496314658,
            'expiry' => 60,
            'expiry_timestamp' => 1496314718,
            'payee_node_key' => '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
            'signature' => str_repeat('ab', 64),
            'recovery_flag' => 1,
            'payment_hash' => str_repeat('01', 32),
            'payment_secret' => str_repeat('11', 32),
            'description' => 'coffee',
            'description_hash' => null,
            'min_final_cltv_expiry_delta' => 40,
            'metadata' => '01fafaf0',
            'features' => [8, 14],
            'fallback_addresses' => [['version' => 0, 'program' => '751e76e8199196d454941c45d1b3a323f1433bd6', 'address' => 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx']],
            'route_hints' => [[['public_key' => '02'.str_repeat('aa', 32), 'short_channel_id' => '0102030405060708', 'fee_base_msat' => 1, 'fee_proportional_millionths' => 20, 'cltv_expiry_delta' => 3]]],
            'unknown_fields' => [['type' => 10, 'words' => [0, 0, 0]]],
        ];

        self::assertSame($expected, $paymentRequest->toArray());
        self::assertSame(json_encode($expected, JSON_THROW_ON_ERROR), json_encode($paymentRequest, JSON_THROW_ON_ERROR));
    }

    public function testFallbackAddressAndRouteHintHop(): void
    {
        $segwit = new FallbackAddress(1, str_repeat('00', 32), 'bc1p...');
        $p2sh = new FallbackAddress(FallbackAddress::VERSION_P2SH, str_repeat('00', 20), '3...');
        self::assertTrue($segwit->isSegwit());
        self::assertFalse($p2sh->isSegwit());
        self::assertSame(str_repeat('00', 32), $segwit->getProgram());

        // Block 589,390, transaction 3,312, output 1 (BOLT #11 vector 10).
        $hop = new RouteHintHop('03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7', '08fe4e000cf00001', 1000, 2500, 40);
        self::assertSame('589390x3312x1', $hop->getShortChannelIdNotation());
    }

    private static function paymentRequest(?int $milliSatoshis = 1000, int $expiry = 3600, ?string $descriptionHash = null): PaymentRequest
    {
        return new PaymentRequest(
            prefix: 'lnbc',
            network: Network::Mainnet,
            milliSatoshis: $milliSatoshis,
            timestamp: new \DateTimeImmutable('@1496314658'),
            payeeNodeKey: '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
            signature: str_repeat('00', 64),
            recoveryFlag: 0,
            paymentHash: str_repeat('00', 32),
            descriptionHash: $descriptionHash,
            expiry: $expiry,
        );
    }
}
