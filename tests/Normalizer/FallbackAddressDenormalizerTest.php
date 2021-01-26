<?php

declare(strict_types=1);

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

        static::assertSame($code, $fallbackAddress->getCode());
        static::assertSame($address, $fallbackAddress->getAddress());
        static::assertSame($addressHash, $fallbackAddress->getAddressHash());
    }
}
