<?php

declare(strict_types=1);

namespace Tests\Jorijn\Bitcoin\Bolt11\Normalizer;

use Jorijn\Bitcoin\Bolt11\Model\RoutingInfo;
use Jorijn\Bitcoin\Bolt11\Normalizer\RoutingInfoDenormalizer;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Jorijn\Bitcoin\Bolt11\Normalizer\RoutingInfoDenormalizer
 *
 * @internal
 */
final class RoutingInfoDenormalizerTest extends TestCase
{
    /**
     * @covers ::denormalize
     */
    public function testDenormalize()
    {
        $pubkey = 'pubkey'.random_int(1000, 2000);
        $shortChannelId = 'sci'.random_int(1000, 2000);
        $feeBaseMsat = random_int(1000, 2000);
        $feeProportionalMillionths = random_int(1000, 2000);
        $cltvExpiryDelta = random_int(1000, 2000);

        $denormalizer = new RoutingInfoDenormalizer();

        // assert array denormalize
        /** @var RoutingInfo[] $routingInfoArray */
        $routingInfoArray = $denormalizer->denormalize([
            [
                'pubkey' => $pubkey,
                'short_channel_id' => $shortChannelId,
                'fee_base_msat' => $feeBaseMsat,
                'fee_proportional_millionths' => $feeProportionalMillionths,
                'cltv_expiry_delta' => $cltvExpiryDelta,
            ],
        ], RoutingInfo::class.'[]');

        static::assertNotEmpty($routingInfoArray);
        static::assertSame($pubkey, $routingInfoArray[0]->getPubKey());
        static::assertSame($shortChannelId, $routingInfoArray[0]->getShortChannelId());
        static::assertSame($feeBaseMsat, $routingInfoArray[0]->getFeeBaseMsat());
        static::assertSame($feeProportionalMillionths, $routingInfoArray[0]->getFeeProportionalMillionths());
        static::assertSame($cltvExpiryDelta, $routingInfoArray[0]->getCltvExpiryDelta());

        // assert single denormalize
        $routingInfo = $denormalizer->denormalize([
            'pubkey' => $pubkey,
            'short_channel_id' => $shortChannelId,
            'fee_base_msat' => $feeBaseMsat,
            'fee_proportional_millionths' => $feeProportionalMillionths,
            'cltv_expiry_delta' => $cltvExpiryDelta,
        ], RoutingInfo::class);

        static::assertSame($pubkey, $routingInfo->getPubKey());
        static::assertSame($shortChannelId, $routingInfo->getShortChannelId());
        static::assertSame($feeBaseMsat, $routingInfo->getFeeBaseMsat());
        static::assertSame($feeProportionalMillionths, $routingInfo->getFeeProportionalMillionths());
        static::assertSame($cltvExpiryDelta, $routingInfo->getCltvExpiryDelta());
    }
}
