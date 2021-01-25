<?php

declare(strict_types=1);

namespace Jorijn\Bitcoin\Bolt11\Normalizer;

use Jorijn\Bitcoin\Bolt11\Model\FallbackAddress;

class FallbackAddressDenormalizer
{
    use DenormalizerTrait;

    /** @noinspection PhpIncompatibleReturnTypeInspection */
    public function denormalize(array $data): FallbackAddress
    {
        return $this->denormalizerDataWithSetters(new FallbackAddress(), $data);
    }
}
