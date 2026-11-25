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

namespace Tests\Jorijn\Bitcoin\Bolt11\Normalizer;

use Jorijn\Bitcoin\Bolt11\Normalizer\FallbackAddressDenormalizer;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Jorijn\Bitcoin\Bolt11\Normalizer\FallbackAddressDenormalizer
 *
 * @internal
 */
final class FallbackAddressDenormalizerTest extends TestCase
{
    /**
     * @covers ::denormalize
     *
     * @uses \Jorijn\Bitcoin\Bolt11\Model\FallbackAddress
     * @uses \Jorijn\Bitcoin\Bolt11\Normalizer\DenormalizerTrait
     */
    public function testDenormalize(): void
    {
        $denormalizer = new FallbackAddressDenormalizer();

        $code = random_int(1, 10);
        $address = 'address'.random_int(1000, 2000);
        $addressHash = 'addresshash'.random_int(1000, 2000);

        $fallbackAddress = $denormalizer->denormalize([
            'code' => $code,
            'address' => $address,
            'addressHash' => $addressHash,
        ]);

        self::assertSame($code, $fallbackAddress->getCode());
        self::assertSame($address, $fallbackAddress->getAddress());
        self::assertSame($addressHash, $fallbackAddress->getAddressHash());
    }
}
